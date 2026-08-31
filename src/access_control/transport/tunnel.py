"""Local port forward anchored at an SSH hop.

``ssh -L <local>:<dest_host>:<dest_port> bastion``, in-process.  A listener binds
to loopback; each accepted connection gets its own ``direct-tcpip`` channel from
the hop, and bytes are pumped both ways until either side closes.

This is what carries WinRM (5985) and RDP (3389) to machines that are only
reachable from the bastion.  Binding is to ``127.0.0.1`` only -- a forward to a
production server must not be exposed to the rest of the network.
"""

from __future__ import annotations

import select
import socket
import sys
import threading
from typing import TYPE_CHECKING

from ..errors import ConnectionFailed

if TYPE_CHECKING:  # pragma: no cover
    from .ssh import SSHHop

BUFFER_SIZE = 32768
ACCEPT_POLL_S = 0.5


class LocalTunnel:
    """A loopback listener forwarding to ``dest_host:dest_port`` via ``hop``."""

    def __init__(
        self,
        hop: "SSHHop",
        dest_host: str,
        dest_port: int,
        *,
        local_port: int = 0,
        bind_address: str = "127.0.0.1",
    ) -> None:
        self.hop = hop
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.bind_address = bind_address
        self._requested_port = local_port
        self.local_port: int | None = None
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._workers: list[threading.Thread] = []
        self._stop = threading.Event()
        self.connections = 0
        self.errors: list[str] = []

    # -- lifecycle --------------------------------------------------------

    def start(self) -> int:
        """Bind, start accepting, and return the local port in use."""
        if self.local_port is not None:
            return self.local_port

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform == "win32":
            # Exclusive bind: a busy port errors instead of being shared, and
            # no other local process can later steal this credentialed forward
            # out from under us (plain SO_REUSEADDR permits both on Windows).
            server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.bind_address, self._requested_port))
        except OSError as exc:
            server.close()
            raise ConnectionFailed(
                f"cannot bind local port {self._requested_port or '(auto)'} for the tunnel "
                f"to {self.dest_host}:{self.dest_port} ({exc})"
            ) from exc
        server.listen(16)
        server.settimeout(ACCEPT_POLL_S)

        self._server = server
        self.local_port = server.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._accept_loop,
            name=f"ac-tunnel-{self.local_port}->{self.dest_host}:{self.dest_port}",
            daemon=True,
        )
        self._thread.start()
        return self.local_port

    def stop(self) -> None:
        """Stop accepting and tear down every open connection."""
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3)
            self._thread = None
        for worker in list(self._workers):
            if worker.is_alive():
                worker.join(timeout=1)
        self._workers.clear()
        self.local_port = None

    def __enter__(self) -> "LocalTunnel":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.local_port}"

    @property
    def active(self) -> bool:
        return self.local_port is not None and not self._stop.is_set()

    # -- internals --------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            server = self._server
            if server is None:
                return
            try:
                client, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            self.connections += 1
            worker = threading.Thread(
                target=self._serve, args=(client,), name="ac-tunnel-conn", daemon=True
            )
            self._workers.append(worker)
            worker.start()
            self._workers = [w for w in self._workers if w.is_alive()]

    def _serve(self, client: socket.socket) -> None:
        channel = None
        try:
            channel = self.hop.open_forward(self.dest_host, self.dest_port)
            self._pump(client, channel)
        except Exception as exc:  # noqa: BLE001 - one dead connection must not kill the tunnel
            self.errors.append(str(exc))
        finally:
            for sock in (channel, client):
                try:
                    if sock is not None:
                        sock.close()
                except Exception:  # noqa: BLE001
                    pass

    @staticmethod
    def _pump(client: socket.socket, channel) -> None:
        """Shuttle bytes between the local socket and the SSH channel."""
        client.setblocking(False)
        channel.setblocking(False)
        while True:
            readable, _, _ = select.select([client, channel], [], [], 1.0)
            if client in readable:
                data = client.recv(BUFFER_SIZE)
                if not data:
                    return
                channel.sendall(data)
            if channel in readable:
                data = channel.recv(BUFFER_SIZE)
                if not data:
                    return
                client.sendall(data)
            if channel.exit_status_ready() and not readable:
                return


#: RFC 4254 channel-open failure codes. The distinction between 1 and 2 is the
#: whole game: 1 means the bastion refuses to forward at all, 2 means forwarding
#: works and the destination simply did not answer.
SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1
SSH_OPEN_CONNECT_FAILED = 2


def forwarding_permitted(hop: "SSHHop", timeout: float = 8.0) -> tuple[bool, str]:
    """Does this bastion permit ``direct-tcpip`` forwarding at all?

    Everything downstream depends on the answer, and it is the single most
    common reason a chain that "should" work does not: ``AllowTcpForwarding no``
    in the bastion's sshd config makes every jump impossible, no matter how the
    inventory is written.

    Asked by attempting a forward to a port that certainly is not listening. If
    the server refuses the *channel* the answer is no; if it accepts the channel
    and merely fails to connect, forwarding is available.

    Returns ``(permitted, explanation)``.
    """
    import logging

    import paramiko

    # The probe deliberately fails, and Paramiko logs that at ERROR level
    # ("Secsh channel open FAILED"). Printing it would make a successful check
    # look like a fault, so it is silenced for the duration of the attempt.
    transport_log = logging.getLogger("paramiko.transport")
    previous_level = transport_log.level
    transport_log.setLevel(logging.CRITICAL)

    try:
        channel = hop.transport.open_channel(
            "direct-tcpip",
            dest_addr=("127.0.0.1", 1),  # port 1: reserved, never listening
            src_addr=("127.0.0.1", 0),
            timeout=timeout,
        )
    except paramiko.ChannelException as exc:
        code = exc.args[0] if exc.args else None
        if code == SSH_OPEN_ADMINISTRATIVELY_PROHIBITED:
            return False, (
                "the bastion refused the forwarding channel "
                "(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED). Its sshd config has "
                "'AllowTcpForwarding no', or a Match block disables it for this user. "
                "No jump through this host is possible until that changes -- there is no "
                "client-side workaround. Ask whoever owns the bastion."
            )
        if code == SSH_OPEN_CONNECT_FAILED:
            return True, "forwarding is permitted (the probe destination refused, as expected)"
        return True, f"forwarding appears permitted (channel error {code}: {exc})"
    except Exception as exc:  # noqa: BLE001 - any other failure is inconclusive
        return True, f"could not determine conclusively ({exc}); assuming permitted"
    else:
        # Unexpected: something answered on port 1. Forwarding clearly works.
        try:
            channel.close()
        except Exception:  # noqa: BLE001
            pass
        return True, "forwarding is permitted"
    finally:
        transport_log.setLevel(previous_level)


def port_open_via(hop: "SSHHop", host: str, port: int, timeout: float = 6.0) -> bool:
    """Can ``host:port`` be reached *from* ``hop``?

    Opening a ``direct-tcpip`` channel and immediately closing it is the cheapest
    honest answer: the bastion only completes the channel if the destination
    actually accepted a connection.
    """
    channel = None
    try:
        channel = hop.transport.open_channel(
            "direct-tcpip",
            dest_addr=(host, port),
            src_addr=("127.0.0.1", 0),
            timeout=timeout,
        )
        return channel is not None
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        return False
    finally:
        if channel is not None:
            try:
                channel.close()
            except Exception:  # noqa: BLE001
                pass


def port_open_direct(host: str, port: int, timeout: float = 6.0) -> bool:
    """Can ``host:port`` be reached from this machine, with no hop?"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
