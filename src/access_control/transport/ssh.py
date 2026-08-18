"""SSH transport, chained hop to hop.

Each hop after the first is reached over a ``direct-tcpip`` channel opened on the
hop before it -- the same mechanism OpenSSH's ``ProxyJump`` uses.  Paramiko is
used rather than the system ``ssh`` client for three reasons:

* Windows OpenSSH has no ``ControlMaster``, so connection reuse across a
  multi-step run has to happen in-process.
* Per-hop passwords cannot be fed to the system client non-interactively on
  Windows (there is no ``sshpass``).
* Multi-factor chains (``publickey`` *then* ``password``, per PLAN.md's "we
  access bastion through key + password") need explicit control over the
  authentication sequence.
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path
from typing import Any, Sequence

import paramiko

# Not re-exported at paramiko's top level (as of 5.0), and it is the exception
# that carries the key+password chain: the server accepted the key and is asking
# for the next factor.
from paramiko.ssh_exception import PartialAuthentication

from ..audit import EV_HOP_AUTH, EV_HOP_CONNECTED, EV_HOP_FAILED, AuditLog
from ..config import Node
from ..credentials import CredentialStore
from ..errors import ConnectionFailed
from .base import ExecResult
from .pshell import parse_exit, powershell_command_line

DEFAULT_CONNECT_TIMEOUT = 30
DEFAULT_BANNER_TIMEOUT = 30

#: ``strict`` refuses an unknown host key; ``accept-new`` records it and
#: continues (OpenSSH's own default for first contact).  A *changed* key is
#: always fatal under both -- that is the case that indicates interception.
HOST_KEY_POLICY = os.environ.get("AC_HOST_KEY_POLICY", "accept-new").lower()


# --------------------------------------------------------------------------
# Key loading
# --------------------------------------------------------------------------


def _key_classes() -> list[type[paramiko.PKey]]:
    names = ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey")
    return [cls for cls in (getattr(paramiko, n, None) for n in names) if cls is not None]


def looks_like_putty_key(path: Path) -> bool:
    """PuTTY ``.ppk`` files are not OpenSSH keys and Paramiko cannot read them."""
    try:
        with path.open("rb") as handle:
            return handle.read(32).startswith(b"PuTTY-User-Key-File")
    except OSError:
        return False


def load_private_key(path: Path, passphrase: str | None = None) -> paramiko.PKey:
    """Load a private key, trying every format Paramiko supports.

    Raises :class:`~..errors.ConnectionFailed` with actionable guidance for the
    two failures that actually happen in practice: a ``.ppk`` file, and a key
    that needs a passphrase.
    """
    if not path.exists():
        raise ConnectionFailed(
            f"key file not found: {path}\n"
            f"Check 'key_file' for this hop in inventory.yaml."
        )
    if looks_like_putty_key(path):
        raise ConnectionFailed(
            f"{path} is a PuTTY .ppk key, which Paramiko cannot read.\n"
            f"Convert it once with PuTTYgen:\n"
            f"    puttygen \"{path}\" -O private-openssh -o \"{path.with_suffix('.pem')}\"\n"
            f"then point 'key_file' at the .pem result."
        )

    needs_passphrase = False
    errors: list[str] = []
    for cls in _key_classes():
        try:
            return cls.from_private_key_file(str(path), password=passphrase)
        except paramiko.PasswordRequiredException:
            needs_passphrase = True
        except paramiko.SSHException as exc:
            errors.append(f"{cls.__name__}: {exc}")
        except OSError as exc:
            raise ConnectionFailed(f"cannot read key file {path}: {exc}") from exc

    if needs_passphrase:
        raise paramiko.PasswordRequiredException(str(path))
    raise ConnectionFailed(
        f"{path} is not a private key in any format Paramiko understands.\n"
        + "\n".join(f"  {e}" for e in errors)
    )


# --------------------------------------------------------------------------
# Host key verification
# --------------------------------------------------------------------------


def _known_hosts_path() -> Path:
    override = os.environ.get("AC_KNOWN_HOSTS")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".ssh" / "known_hosts"


def _host_key_names(host: str, port: int) -> list[str]:
    return [host] if port == 22 else [f"[{host}]:{port}", host]


def verify_host_key(
    transport: paramiko.Transport, host: str, port: int, audit: AuditLog | None
) -> str:
    """Check the server's key against ``known_hosts``.

    Returns ``"known"``, ``"new"``, or raises on a mismatch.  A changed key is
    always fatal: it is the signature of an interception, and this tool exists to
    carry credentials to production servers.
    """
    server_key = transport.get_remote_server_key()
    fingerprint = f"{server_key.get_name()} {server_key.get_base64()[:43]}"

    path = _known_hosts_path()
    host_keys = paramiko.HostKeys()
    if path.exists():
        try:
            host_keys.load(str(path))
        except Exception as exc:  # noqa: BLE001
            # A single malformed line must not make every connection impossible.
            # Paramiko raises InvalidHostKey for a corrupt entry; treat the file
            # as empty and fall through to the unknown-key path, which is
            # conservative rather than permissive.
            if audit:
                audit.emit("host_key.unreadable", path=str(path), error=str(exc))

    for name in _host_key_names(host, port):
        entry = host_keys.lookup(name)
        if entry is None:
            continue
        expected = entry.get(server_key.get_name())
        if expected is None:
            continue
        if expected.asbytes() == server_key.asbytes():
            return "known"
        raise ConnectionFailed(
            f"HOST KEY MISMATCH for {name}.\n"
            f"The key offered by {host}:{port} does not match the one in {path}.\n"
            f"This can mean the server was rebuilt -- or that the connection is being "
            f"intercepted. Nothing was sent. Verify with the server owner, then remove the "
            f"stale line from known_hosts if it is legitimate."
        )

    if HOST_KEY_POLICY == "strict":
        raise ConnectionFailed(
            f"unknown host key for {host}:{port} ({fingerprint}) and "
            f"AC_HOST_KEY_POLICY=strict.\n"
            f"Connect once with the system client to record it:\n"
            f"    ssh -p {port} {host}"
        )

    if audit:
        audit.emit(
            "host_key.new",
            host=host,
            port=port,
            fingerprint=fingerprint,
            policy=HOST_KEY_POLICY,
        )
    try:
        host_keys.add(_host_key_names(host, port)[0], server_key.get_name(), server_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        host_keys.save(str(path))
    except OSError:
        pass
    return "new"


# --------------------------------------------------------------------------
# One authenticated SSH hop
# --------------------------------------------------------------------------


class SSHHop:
    """One authenticated SSH connection, optionally reached through another."""

    kind = "ssh"

    def __init__(
        self,
        node: Node,
        transport: paramiko.Transport,
        *,
        username: str,
        audit: AuditLog | None = None,
    ) -> None:
        self.node = node
        self.node_id = node.id
        self.transport = transport
        self.username = username
        self.audit = audit
        self._sftp: paramiko.SFTPClient | None = None

    # -- plumbing ---------------------------------------------------------

    def open_forward(self, dest_host: str, dest_port: int, timeout: float = 20.0):
        """Open a ``direct-tcpip`` channel to ``dest_host:dest_port``.

        The returned channel behaves like a socket, so the next hop's
        :class:`paramiko.Transport` -- or a local port forward -- can ride on it.
        """
        try:
            channel = self.transport.open_channel(
                "direct-tcpip",
                dest_addr=(dest_host, dest_port),
                src_addr=("127.0.0.1", 0),
                timeout=timeout,
            )
        except paramiko.SSHException as exc:
            raise ConnectionFailed(
                f"{self.node_id}: cannot open a forward to {dest_host}:{dest_port} ({exc}).\n"
                f"The bastion may forbid forwarding, or the destination may be unreachable "
                f"from it. Check with: ssh {self.node.host} 'nc -vz {dest_host} {dest_port}'"
            ) from exc
        if channel is None:
            raise ConnectionFailed(
                f"{self.node_id}: forward to {dest_host}:{dest_port} was refused by the server."
            )
        return channel

    def sftp(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            client = paramiko.SFTPClient.from_transport(self.transport)
            if client is None:
                raise ConnectionFailed(f"{self.node_id}: cannot open an SFTP session")
            self._sftp = client
        return self._sftp

    @property
    def active(self) -> bool:
        return bool(self.transport and self.transport.is_active())

    # -- execution --------------------------------------------------------

    def exec(
        self,
        command: str,
        *,
        shell: str = "bash",
        timeout_s: int = 600,
        sudo: bool = False,
        sudo_password: str | None = None,
    ) -> ExecResult:
        """Run one command and collect its output."""
        started = time.monotonic()
        wire_command, is_powershell = self._build_command(command, shell, sudo)

        try:
            channel = self.transport.open_session(timeout=30)
        except paramiko.SSHException as exc:
            raise ConnectionFailed(f"{self.node_id}: cannot open a session ({exc})") from exc

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        timed_out = False
        exit_code: int | None = None

        try:
            channel.settimeout(float(timeout_s))
            channel.exec_command(wire_command)

            if sudo and sudo_password:
                channel.sendall((sudo_password + "\n").encode())

            deadline = time.monotonic() + timeout_s
            while True:
                if channel.recv_ready():
                    stdout_chunks.append(channel.recv(65536))
                if channel.recv_stderr_ready():
                    stderr_chunks.append(channel.recv_stderr(65536))
                if channel.exit_status_ready() and not (
                    channel.recv_ready() or channel.recv_stderr_ready()
                ):
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                time.sleep(0.02)

            while channel.recv_ready():
                stdout_chunks.append(channel.recv(65536))
            while channel.recv_stderr_ready():
                stderr_chunks.append(channel.recv_stderr(65536))

            if not timed_out:
                exit_code = channel.recv_exit_status()
        except socket.timeout:
            timed_out = True
        finally:
            try:
                channel.close()
            except Exception:  # noqa: BLE001 - closing must never mask the result
                pass

        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")

        if is_powershell:
            stdout, sentinel_code = parse_exit(stdout)
            if sentinel_code is not None:
                exit_code = sentinel_code

        return ExecResult(
            node_id=self.node_id,
            channel="ssh",
            command=command,
            exit_code=exit_code if not timed_out else None,
            stdout=stdout,
            stderr=stderr,
            duration_s=time.monotonic() - started,
            timed_out=timed_out,
        )

    def _build_command(self, command: str, shell: str, sudo: bool) -> tuple[str, bool]:
        """Turn a step's script into the exact line sent over the wire."""
        if shell == "powershell":
            # Works for Windows targets running OpenSSH Server, and for Linux
            # hosts with pwsh installed. Encoded, so nothing can be re-quoted.
            return powershell_command_line(command), True
        if sudo:
            # -S reads the password from stdin; -p '' suppresses sudo's own
            # prompt so it cannot be mistaken for command output.
            return f"sudo -S -p '' -- {shell} -c {_sh_quote(command)}", False
        return command, False

    # -- file transfer ----------------------------------------------------

    def upload(self, local_path: str, remote_path: str) -> None:
        self.sftp().put(str(local_path), str(remote_path))

    def fetch(self, remote_path: str, local_path: str) -> None:
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        self.sftp().get(str(remote_path), str(local_path))

    # -- teardown ---------------------------------------------------------

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:  # noqa: BLE001
                pass
            self._sftp = None
        try:
            self.transport.close()
        except Exception:  # noqa: BLE001
            pass


def _sh_quote(value: str) -> str:
    """POSIX single-quote a string for a remote shell."""
    return "'" + value.replace("'", "'\\''") + "'"


# --------------------------------------------------------------------------
# Connecting
# --------------------------------------------------------------------------


def _authenticate(
    transport: paramiko.Transport,
    node: Node,
    username: str,
    creds: CredentialStore,
    label: str,
    audit: AuditLog | None,
) -> list[str]:
    """Run the authentication sequence for one hop.

    Handles the ``publickey``-then-``password`` chain that ``AuthenticationMethods
    publickey,password`` on the server requires, and falls through to
    keyboard-interactive so an MFA challenge reaches the operator verbatim.

    Returns the list of methods that actually succeeded, for the audit trail.
    """
    auth = node.auth
    used: list[str] = []
    remaining: Sequence[str] = ()
    #: Set when the server refused the public key but a password stage follows.
    key_rejected: str | None = None

    def _note(method: str) -> None:
        used.append(method)
        if audit:
            audit.emit(EV_HOP_AUTH, hop_id=node.id, method=method, username=username)

    if auth.method == "agent":
        agent_keys = paramiko.Agent().get_keys()
        if not agent_keys:
            raise ConnectionFailed(
                f"{label}: auth method is 'agent' but the SSH agent offers no keys.\n"
                f"Start the agent and add your key:  ssh-add <key file>"
            )
        for key in agent_keys:
            try:
                transport.auth_publickey(username, key)
                _note("agent")
                return used
            except PartialAuthentication as exc:
                remaining = exc.allowed_types
                _note("agent")
                break
            except paramiko.AuthenticationException:
                continue
        else:
            raise ConnectionFailed(f"{label}: no key in the SSH agent was accepted")

    if auth.uses_key and not transport.is_authenticated():
        cred = creds.acquire(
            node.id,
            label=label,
            username=username,
            need_password=False,
            key_file=auth.key_file,
        )
        try:
            pkey = load_private_key(auth.key_file, cred.key_passphrase)  # type: ignore[arg-type]
        except paramiko.PasswordRequiredException:
            cred = creds.acquire(
                node.id,
                label=label,
                username=username,
                need_password=False,
                key_file=auth.key_file,
                need_key_passphrase=True,
            )
            pkey = load_private_key(auth.key_file, cred.key_passphrase)  # type: ignore[arg-type]

        try:
            transport.auth_publickey(username, pkey)
            _note("publickey")
        except PartialAuthentication as exc:
            # The server wants another factor -- exactly the key+password case.
            remaining = exc.allowed_types
            _note("publickey")
        except paramiko.BadAuthenticationType as exc:
            remaining = exc.allowed_types
        except paramiko.AuthenticationException as exc:
            if not auth.uses_password:
                raise ConnectionFailed(
                    f"{label}: public key authentication was rejected ({exc}).\n"
                    f"Confirm {auth.key_file} is the right key and that its public half is "
                    f"in ~/.ssh/authorized_keys on the server."
                ) from exc
            # Remember it. With `AuthenticationMethods publickey,password` the
            # server requires BOTH, so once the key is refused no password can
            # succeed -- and reporting only the password failure sends people
            # retyping a credential that was never the problem.
            key_rejected = str(exc) or "rejected"

    wants_password = auth.uses_password or "password" in remaining
    if wants_password and not transport.is_authenticated():
        cred = creds.acquire(node.id, label=label, username=username, need_password=True)
        try:
            transport.auth_password(username, cred.password or "", fallback=False)
            _note("password")
        except PartialAuthentication as exc:
            remaining = exc.allowed_types
            _note("password")
        except paramiko.AuthenticationException as exc:
            if "keyboard-interactive" not in remaining:
                creds.discard(node.id)
                raise ConnectionFailed(
                    f"{label}: password authentication failed.\n"
                    + (
                        f"NOTE: the public key ({auth.key_file}) was ALREADY REJECTED for "
                        f"'{username}' before this. This server requires publickey AND "
                        f"password, so no password can succeed until the key is accepted. "
                        f"The password is probably not the problem.\n"
                        f"Most often the username is wrong: a key is enrolled against one "
                        f"account, and '{username}' is not it. Check what you log in as by "
                        f"hand, and the 'username'/'domain' for this node in inventory.yaml.\n"
                        if key_rejected
                        else ""
                    )
                    + f"The password was not stored; you will be prompted again on retry."
                ) from exc

    if not transport.is_authenticated():
        # Either the server asked for it, or nothing else has worked yet.
        def handler(title: str, instructions: str, prompts: Sequence[tuple[str, bool]]) -> list[str]:
            banner = " / ".join(p for p in (title.strip(), instructions.strip()) if p)
            return creds.answer_challenge(
                node.id, f"{label}{f' - {banner}' if banner else ''}", prompts
            )

        try:
            transport.auth_interactive(username, handler)  # type: ignore[arg-type]
            _note("keyboard-interactive")
        except paramiko.AuthenticationException as exc:
            creds.discard(node.id)
            raise ConnectionFailed(
                f"{label}: authentication failed after trying "
                f"{', '.join(used) or 'no methods'}.\n"
                f"Nothing was stored; you will be prompted again on retry."
            ) from exc

    if not transport.is_authenticated():
        raise ConnectionFailed(f"{label}: authentication did not complete")

    creds.note_authenticated(node.id)
    return used


def connect_hop(
    node: Node,
    creds: CredentialStore,
    *,
    via: SSHHop | None = None,
    audit: AuditLog | None = None,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    endpoint: Any = None,
) -> SSHHop:
    """Authenticate to one SSH node, optionally through an existing hop.

    ``endpoint`` is the address declared for this leg of the route. It is used in
    preference to the node's own fields because the same machine is addressed
    differently depending on where you are standing -- and a pre-established
    forward (``localhost:44001``) must be dialled directly rather than tunnelled
    through the hop a second time.
    """
    address = endpoint.hostname if endpoint is not None else node.host
    port = endpoint.port if endpoint is not None else node.port
    preestablished = bool(endpoint is not None and endpoint.preestablished)
    label = _hop_label(node, via, address=address, port=port)
    started = time.monotonic()

    if via is not None and not preestablished:
        sock: Any = via.open_forward(address, port)
    else:
        try:
            sock = socket.create_connection((address, port), timeout=connect_timeout)
        except OSError as exc:
            if audit:
                audit.emit(EV_HOP_FAILED, hop_id=node.id, stage="tcp", error=str(exc))
            raise ConnectionFailed(
                f"{label}: cannot reach {address}:{port} ({exc}).\n"
                + (
                    f"This hop is declared as a pre-established forward, so something else "
                    f"is expected to be listening on {address}:{port} already. Start that "
                    f"tunnel, or remove 'preestablished' and let this tool build it."
                    if preestablished
                    else "Check the address and port declared for this hop in inventory.yaml, "
                    "and whether you need to be on the VPN."
                )
            ) from exc

    transport = paramiko.Transport(sock)
    transport.banner_timeout = DEFAULT_BANNER_TIMEOUT
    # Keep the chain alive across long-running steps; a bastion that drops idle
    # connections would otherwise kill a patch run mid-flight.
    transport.set_keepalive(30)
    # Paramiko 5's default host key preference dropped plain 'ssh-rsa' in favor
    # of rsa-sha2-256/512. Some of our production bastions are old enough to
    # offer only 'ssh-rsa', so without this the handshake fails with "no
    # acceptable host key" before verify_host_key() ever runs. Appended, not
    # substituted, so newer algorithms are still preferred where offered -- and
    # the actual key is still pinned against known_hosts either way, so this
    # only widens which signature algorithm is acceptable, not which key is.
    security = transport.get_security_options()
    if "ssh-rsa" not in security.key_types:
        security.key_types = security.key_types + ("ssh-rsa",)

    try:
        transport.start_client(timeout=connect_timeout)
    except paramiko.SSHException as exc:
        transport.close()
        if audit:
            audit.emit(EV_HOP_FAILED, hop_id=node.id, stage="handshake", error=str(exc))
        raise ConnectionFailed(f"{label}: SSH handshake failed ({exc})") from exc

    try:
        key_state = verify_host_key(transport, address, port, audit)
        username = (
            node.qualified_user or os.environ.get("USERNAME") or os.environ.get("USER") or ""
        )
        if node.auth.prompt_username or not username:
            cred = creds.acquire(
                node.id,
                label=label,
                username=username or None,
                need_password=False,
                prompt_username=True,
            )
            username = cred.username or username
        methods = _authenticate(transport, node, username, creds, label, audit)
    except Exception:
        transport.close()
        raise

    hop = SSHHop(node, transport, username=username, audit=audit)
    if audit:
        audit.action(
            "SSH_CONNECT",
            source=via.node_id if via else "local",
            target=node.id,
            result="SUCCESS",
            hop_id=node.id,
            endpoint=f"{address}:{port}",
            channel="ssh",
            username=username,
            domain=node.domain,
            auth_methods=methods,
            host_key=key_state,
            preestablished=preestablished,
            context=node.context.to_dict(),
            duration_s=round(time.monotonic() - started, 2),
        )
    return hop


def connect_chain(
    nodes: Sequence[Node],
    creds: CredentialStore,
    *,
    audit: AuditLog | None = None,
    endpoints: Sequence[Any] | None = None,
) -> list[SSHHop]:
    """Authenticate through a chain of SSH nodes, in order.

    On any failure every hop already opened is closed, so a half-built chain
    never lingers holding credentials.
    """
    hops: list[SSHHop] = []
    try:
        for index, node in enumerate(nodes):
            endpoint = endpoints[index] if endpoints is not None else None
            hops.append(
                connect_hop(
                    node,
                    creds,
                    via=hops[-1] if hops else None,
                    audit=audit,
                    endpoint=endpoint,
                )
            )
    except Exception:
        for hop in reversed(hops):
            hop.close()
        raise
    return hops


def _hop_label(node: Node, via: SSHHop | None, *, address: str = "", port: int = 0) -> str:
    """What the operator sees on the password prompt.

    Must be unambiguous about which machine is being authenticated to -- typing a
    bastion password into a target server's prompt is exactly the mistake this
    label exists to prevent, so it names the role, the identity, the address and
    the hop it is reached through.
    """
    user = f"{node.qualified_user}@" if node.qualified_user else ""
    through = f" via {via.node_id}" if via else ""
    role = node.description or node.id
    where = f"{address or node.host}:{port or node.port}"
    context = node.context.environment
    env = f" [{context}]" if context else ""
    return f"{role}{env} [{user}{where}]{through}"
