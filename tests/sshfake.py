"""A real SSH server, in-process, for end-to-end tests.

Mocking Paramiko would prove nothing about the part most likely to break: the
multi-hop chain itself.  This is an actual SSH server built on Paramiko's server
API, so the tests exercise a genuine handshake, genuine ``publickey``-then-
``password`` multi-factor authentication, genuine ``exec`` with exit statuses,
and genuine ``direct-tcpip`` forwarding -- which is how one hop reaches the next.

Two of these chained together reproduce the bastion → target shape over real
sockets on localhost.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import paramiko

#: Generating a host key costs about a second, so every server shares one.
_HOST_KEY: paramiko.RSAKey | None = None


def host_key() -> paramiko.RSAKey:
    global _HOST_KEY
    if _HOST_KEY is None:
        _HOST_KEY = paramiko.RSAKey.generate(2048)
    return _HOST_KEY


@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0


Responder = Callable[[str], CommandResult]


@dataclass
class AuthPolicy:
    """What this server demands.  Mirrors ``AuthenticationMethods`` on a real host."""

    username: str = "opuser"
    password: str | None = "bastion-password"
    #: Require a key *and then* a password, the shape PLAN.md describes for the
    #: bastion ("key + password").
    require_key_then_password: bool = False
    accept_any_key: bool = True
    attempts: list[str] = field(default_factory=list)


class _Interface(paramiko.ServerInterface):
    def __init__(self, policy: AuthPolicy, allow_forward: bool) -> None:
        self.policy = policy
        self.allow_forward = allow_forward
        self.exec_commands: dict[int, str] = {}
        self.forward_targets: dict[int, tuple[str, int]] = {}
        self.exec_ready = threading.Event()

    # -- auth -------------------------------------------------------------

    def get_allowed_auths(self, username: str) -> str:
        return "publickey,password,keyboard-interactive"

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.policy.attempts.append("publickey")
        if username != self.policy.username or not self.policy.accept_any_key:
            return paramiko.common.AUTH_FAILED
        if self.policy.require_key_then_password:
            # Exactly what OpenSSH sends for `AuthenticationMethods
            # publickey,password`: the key was fine, keep going.
            return paramiko.common.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.common.AUTH_SUCCESSFUL

    def check_auth_password(self, username: str, password: str) -> int:
        self.policy.attempts.append("password")
        if username == self.policy.username and password == self.policy.password:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    # -- channels ---------------------------------------------------------

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.common.OPEN_SUCCEEDED
        return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.exec_commands[channel.get_id()] = command.decode("utf-8", errors="replace")
        self.exec_ready.set()
        return True

    def check_channel_direct_tcpip_request(
        self, chanid: int, origin: tuple[str, int], destination: tuple[str, int]
    ) -> int:
        if not self.allow_forward:
            return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.forward_targets[chanid] = destination
        return paramiko.common.OPEN_SUCCEEDED


class FakeSSHServer:
    """A listening SSH server that runs scripted commands and forwards TCP."""

    def __init__(
        self,
        name: str = "fake",
        *,
        responder: Responder | None = None,
        policy: AuthPolicy | None = None,
        allow_forward: bool = True,
    ) -> None:
        self.name = name
        self.responder = responder or (lambda cmd: CommandResult(stdout=f"ran: {cmd}"))
        self.policy = policy or AuthPolicy()
        self.allow_forward = allow_forward
        self.port = 0
        self.commands: list[str] = []
        self.forwards: list[tuple[str, int]] = []
        self._socket: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    # -- lifecycle --------------------------------------------------------

    def start(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        server.settimeout(0.5)
        self._socket = server
        self.port = server.getsockname()[1]
        thread = threading.Thread(target=self._accept_loop, name=f"sshfake-{self.name}", daemon=True)
        thread.start()
        self._threads.append(thread)
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        for thread in self._threads:
            thread.join(timeout=3)
        self._threads.clear()

    def __enter__(self) -> "FakeSSHServer":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # -- internals --------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            server = self._socket
            if server is None:
                return
            try:
                client, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(
                target=self._serve_connection, args=(client,), daemon=True
            )
            thread.start()
            self._threads.append(thread)

    def _serve_connection(self, client: socket.socket) -> None:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key())
        interface = _Interface(self.policy, self.allow_forward)
        try:
            transport.start_server(server=interface)
        except paramiko.SSHException:
            transport.close()
            return

        try:
            while not self._stop.is_set() and transport.is_active():
                channel = transport.accept(timeout=0.5)
                if channel is None:
                    continue
                threading.Thread(
                    target=self._serve_channel, args=(channel, interface), daemon=True
                ).start()
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass

    def _serve_channel(self, channel: paramiko.Channel, interface: _Interface) -> None:
        chanid = channel.get_id()
        destination = interface.forward_targets.get(chanid)
        if destination is not None:
            self.forwards.append(destination)
            self._pump_forward(channel, destination)
            return

        # A session channel: wait briefly for the exec request to arrive.
        deadline = time.monotonic() + 5
        while chanid not in interface.exec_commands and time.monotonic() < deadline:
            time.sleep(0.01)

        command = interface.exec_commands.pop(chanid, None)
        if command is None:
            channel.close()
            return

        self.commands.append(command)
        result = self.responder(command)
        try:
            if result.stdout:
                channel.sendall(result.stdout.encode())
            if result.stderr:
                channel.sendall_stderr(result.stderr.encode())
            channel.send_exit_status(result.exit_status)
        except (OSError, paramiko.SSHException):
            pass
        finally:
            try:
                channel.close()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _pump_forward(channel: paramiko.Channel, destination: tuple[str, int]) -> None:
        """Connect onward and shuttle bytes -- this is what makes hop chaining real."""
        import select

        try:
            upstream = socket.create_connection(destination, timeout=10)
        except OSError:
            channel.close()
            return
        try:
            channel.setblocking(False)
            upstream.setblocking(False)
            while True:
                readable, _, _ = select.select([channel, upstream], [], [], 1.0)
                if channel in readable:
                    data = channel.recv(32768)
                    if not data:
                        return
                    upstream.sendall(data)
                if upstream in readable:
                    data = upstream.recv(32768)
                    if not data:
                        return
                    channel.sendall(data)
        except (OSError, paramiko.SSHException):
            return
        finally:
            for sock in (upstream, channel):
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass
