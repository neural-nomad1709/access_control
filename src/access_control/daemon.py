"""Keeping an authenticated session alive between calls.

Building the hop chain costs the operator a password at every hop.  Doing that
per command would make a twenty-step patch run unusable, and Windows OpenSSH has
no ``ControlMaster`` to lean on -- so the session is held in a process of its own
and driven over a loopback socket.

The shape that falls out of the credential rule:

* ``ac connect`` runs **in the operator's own terminal**, in the foreground.
  That is the only place a ``getpass`` prompt can appear, so that is where the
  passwords are typed.  The window stays open for the life of the task, which is
  also what PLAN.md asks for.
* ``ac run``/``ac exec`` are thin clients.  They attach to that session by host
  id and never see a credential.

Access control on the socket: it binds to ``127.0.0.1`` only, and every request
must carry a random per-session token that is written to a descriptor file under
``%LOCALAPPDATA%`` (a per-user directory).  Any process running as this user
could read that file -- this is a convenience boundary, not a privilege one, and
it is documented as such in docs/design.md.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .config import Catalog, Inventory, load_all
from .context import AgentIdentity
from .credentials import CredentialStore, select_prompter
from .engine import Engine, tail_command
from .errors import AccessControlError, SessionError
from .gatekeeper import Gatekeeper
from .paths import ensure_dir, session_dir
from .preflight import run_preflight
from .route import plan_route
from .session import Session
from .transport.tunnel import LocalTunnel

PROTOCOL_VERSION = 1
RECV_LIMIT = 8 * 1024 * 1024
WATCHDOG_INTERVAL_S = 15


# --------------------------------------------------------------------------
# Descriptor files
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionDescriptor:
    host_id: str
    session_id: str
    port: int
    token: str
    pid: int
    started: float
    agent_id: str

    @property
    def path(self) -> Path:
        return descriptor_path(self.host_id)

    def write(self) -> Path:
        path = self.path
        ensure_dir(path.parent)
        payload = {
            "version": PROTOCOL_VERSION,
            "host_id": self.host_id,
            "session_id": self.session_id,
            "port": self.port,
            "token": self.token,
            "pid": self.pid,
            "started": self.started,
            "agent_id": self.agent_id,
        }
        # Create with restrictive permissions before anything is written, so the
        # token is never briefly world-readable.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        handle = os.open(str(path), flags, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return path

    def remove(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def descriptor_path(host_id: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in host_id)
    return session_dir() / f"{safe}.json"


def read_descriptor(host_id: str) -> SessionDescriptor | None:
    path = descriptor_path(host_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("version") != PROTOCOL_VERSION:
        return None
    try:
        return SessionDescriptor(
            host_id=data["host_id"],
            session_id=data["session_id"],
            port=int(data["port"]),
            token=data["token"],
            pid=int(data.get("pid", 0)),
            started=float(data.get("started", 0)),
            agent_id=data.get("agent_id", ""),
        )
    except (KeyError, TypeError, ValueError):
        return None


def list_descriptors() -> list[SessionDescriptor]:
    base = session_dir()
    if not base.exists():
        return []
    out: list[SessionDescriptor] = []
    for path in sorted(base.glob("*.json")):
        descriptor = read_descriptor(path.stem)
        if descriptor is not None:
            out.append(descriptor)
    return out


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class SessionClient:
    """Talks to a running :class:`SessionServer` over loopback."""

    def __init__(self, descriptor: SessionDescriptor, timeout: float = 3600.0) -> None:
        self.descriptor = descriptor
        self.timeout = timeout

    def call(self, method: str, **params: Any) -> Any:
        request = json.dumps(
            {"token": self.descriptor.token, "method": method, "params": params}
        ).encode()

        try:
            with socket.create_connection(("127.0.0.1", self.descriptor.port), timeout=15) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(request + b"\n")
                buffer = bytearray()
                while b"\n" not in buffer:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    if len(buffer) > RECV_LIMIT:
                        raise SessionError("session response exceeded the size limit")
        except OSError as exc:
            raise SessionError(
                f"the session for '{self.descriptor.host_id}' is not answering ({exc}).\n"
                f"It may have been closed or timed out. Start a new one:\n"
                f"    uv run ac connect {self.descriptor.host_id}"
            ) from exc

        if not buffer:
            raise SessionError(
                f"the session for '{self.descriptor.host_id}' closed without replying"
            )

        response = json.loads(bytes(buffer).split(b"\n", 1)[0].decode())
        if not response.get("ok"):
            raise AccessControlError(response.get("error", "unknown session error"))
        return response.get("result")

    def alive(self) -> bool:
        try:
            self.call("ping")
            return True
        except AccessControlError:
            return False


def attach(host_id: str) -> SessionClient | None:
    """Return a client for a live session on ``host_id``, or ``None``.

    A stale descriptor (the terminal was closed, the machine rebooted) is removed
    rather than left to produce confusing errors later.
    """
    descriptor = read_descriptor(host_id)
    if descriptor is None:
        return None
    client = SessionClient(descriptor)
    if client.alive():
        return client
    descriptor.remove()
    return None


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


class SessionServer:
    """Serves one :class:`Session` on a loopback socket until it is closed."""

    def __init__(self, session: Session, *, on_ready: Callable[[SessionDescriptor], None] | None = None):
        self.session = session
        self.engine = Engine(session)
        self.token = secrets.token_urlsafe(32)
        self.on_ready = on_ready
        self._socket: socket.socket | None = None
        self._descriptor: SessionDescriptor | None = None
        self._stop = threading.Event()
        self._tunnels: dict[int, LocalTunnel] = {}
        self._next_tunnel_id = 1
        self._lock = threading.RLock()
        #: Set by do_close; acted on once the reply has been written.
        self._close_after_reply = False

    # -- lifecycle --------------------------------------------------------

    def serve_forever(self) -> dict[str, Any]:
        """Accept requests until the session is closed or times out.

        Returns the session's closing report, so the caller can show the
        operator a summary before the path disappears.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        server.settimeout(1.0)
        self._socket = server

        self._descriptor = SessionDescriptor(
            host_id=self.session.host_id,
            session_id=self.session.session_id,
            port=server.getsockname()[1],
            token=self.token,
            pid=os.getpid(),
            started=time.time(),
            agent_id=self.session.agent_id,
        )
        self._descriptor.write()
        if self.on_ready is not None:
            self.on_ready(self._descriptor)

        watchdog = threading.Thread(target=self._watchdog, name="ac-idle-watchdog", daemon=True)
        watchdog.start()

        status = "closed"
        try:
            while not self._stop.is_set():
                try:
                    client, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self._handle, args=(client,), name="ac-session-req", daemon=True
                ).start()
        except KeyboardInterrupt:
            status = "interrupted"
        if self.session.expired:
            status = "idle-timeout"
        return self.shutdown(status)

    def shutdown(self, status: str = "closed") -> dict[str, Any]:
        self._stop.set()
        with self._lock:
            tunnels = list(self._tunnels.values())
            self._tunnels.clear()
        for tunnel in tunnels:
            try:
                tunnel.stop()
            except Exception:  # noqa: BLE001
                pass
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        if self._descriptor is not None:
            self._descriptor.remove()
        return self.session.close(status=status)

    def _watchdog(self) -> None:
        """Close the session once it has been idle past its timeout."""
        while not self._stop.wait(WATCHDOG_INTERVAL_S):
            if self.session.expired:
                if self.session.audit:
                    self.session.audit.emit(
                        "session.idle_timeout", idle_s=round(self.session.idle_s, 1)
                    )
                self._stop.set()
                # Nudge accept() out of its timeout so serve_forever returns.
                try:
                    if self._socket is not None:
                        with socket.create_connection(
                            ("127.0.0.1", self._socket.getsockname()[1]), timeout=2
                        ):
                            pass
                except OSError:
                    pass
                return

    # -- request handling -------------------------------------------------

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(3600)
            buffer = bytearray()
            while b"\n" not in buffer:
                chunk = client.recv(65536)
                if not chunk:
                    return
                buffer.extend(chunk)
                if len(buffer) > RECV_LIMIT:
                    self._reply(client, {"ok": False, "error": "request too large"})
                    return

            request = json.loads(bytes(buffer).split(b"\n", 1)[0].decode())
            if not secrets.compare_digest(str(request.get("token", "")), self.token):
                self._reply(client, {"ok": False, "error": "invalid session token"})
                return

            method = str(request.get("method", ""))
            params = request.get("params") or {}
            handler = getattr(self, f"do_{method.replace('-', '_')}", None)
            if handler is None:
                self._reply(client, {"ok": False, "error": f"unknown method '{method}'"})
                return

            result = handler(**params)
            self._reply(client, {"ok": True, "result": result})
        except AccessControlError as exc:
            self._reply(client, {"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        except Exception as exc:  # noqa: BLE001 - one bad request must not kill the session
            self._reply(client, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        finally:
            try:
                client.close()
            except OSError:
                pass
            # Deferred from do_close: the reply is on the wire and the socket is
            # closed, so tearing the listener down now cannot truncate it.
            if self._close_after_reply:
                self._trigger_stop()

    @staticmethod
    def _reply(client: socket.socket, payload: dict[str, Any]) -> None:
        try:
            client.sendall(json.dumps(payload, default=str).encode() + b"\n")
        except OSError:
            pass

    # -- methods (do_* is the wire protocol) -------------------------------

    def do_ping(self) -> dict[str, Any]:
        return {"session_id": self.session.session_id, "host_id": self.session.host_id}

    def do_status(self) -> dict[str, Any]:
        return self.session.status()

    def do_preflight(
        self, spec: dict[str, Any] | None = None, phase: str = "preflight"
    ) -> dict[str, Any]:
        """Verify the connection is live and pointed at the right machine.

        ``phase`` names what the checks are for — "preflight" before a change,
        "postcheck" after one — so the audit trail can tell them apart.
        """
        self.session.touch()
        report = run_preflight(self.session, spec or {})
        if self.session.audit:
            self.session.audit.action(
                "PREFLIGHT",
                target=self.session.host_id,
                result="SUCCESS" if report.ok else "FAILURE",
                detail=f"{phase}: {len(report.checks)} check(s), {len(report.blockers)} blocker(s)",
                phase=phase,
                checks=[c.to_dict() for c in report.checks],
            )
        return report.to_dict()

    def do_operations(self) -> list[dict[str, Any]]:
        return self.session.operations()

    def do_reload(self) -> dict[str, Any]:
        """Re-read operations.yaml without dropping the authenticated session.

        Editing an operation would otherwise mean reconnecting, and reconnecting
        costs the operator a password at every hop -- which makes iterating on a
        runbook painful enough that people stop doing it.

        Only the *catalog* is reloaded. The inventory is re-read solely to check
        the route has not changed underneath us: if it has, the live connection
        no longer matches the config and the honest answer is to reconnect.
        """
        inventory, catalog, warnings = load_all()

        try:
            new_route = plan_route(inventory, self.session.host_id)
        except AccessControlError as exc:
            raise SessionError(
                f"reload failed: '{self.session.host_id}' is no longer valid in "
                f"inventory.yaml ({exc}). The running session is unaffected."
            ) from exc

        if new_route.describe() != self.session.route.describe():
            raise SessionError(
                f"reload refused: the route for '{self.session.host_id}' changed from\n"
                f"    {self.session.route.describe()}\n"
                f"to\n"
                f"    {new_route.describe()}\n"
                f"The live connection no longer matches the config. Reconnect:\n"
                f"    uv run ac disconnect {self.session.host_id} && uv run ac connect {self.session.host_id}"
            )

        before = {op["id"] for op in self.session.operations()}
        self.session.catalog = catalog
        self.session.inventory = inventory
        after = {op["id"] for op in self.session.operations()}

        if self.session.audit:
            self.session.audit.emit(
                "config.reload",
                operations=sorted(after),
                added=sorted(after - before),
                removed=sorted(before - after),
                warnings=warnings,
            )
        self.session.touch()
        return {
            "host_id": self.session.host_id,
            "operations": sorted(after),
            "added": sorted(after - before),
            "removed": sorted(before - after),
            "warnings": warnings,
            "route": self.session.route.describe(),
        }

    def do_preview(self, operation_id: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.session.touch()
        return self.engine.preview(operation_id, params or {})

    def do_run_operation(
        self,
        operation_id: str,
        params: dict[str, Any] | None = None,
        confirmed: bool = False,
        dry_run: bool = False,
        only_steps: list[str] | None = None,
        start_at: str | None = None,
    ) -> dict[str, Any]:
        self.session.touch()
        outcome = self.engine.run_operation(
            operation_id,
            params or {},
            confirmed=confirmed,
            dry_run=dry_run,
            only_steps=only_steps,
            start_at=start_at,
        )
        return outcome.to_dict()

    def do_run_command(
        self,
        command: str,
        shell: str | None = None,
        confirmed: bool = False,
        timeout_s: int = 300,
    ) -> dict[str, Any]:
        self.session.touch()
        return self.engine.run_command(
            command, shell=shell, confirmed=confirmed, timeout_s=timeout_s
        ).to_dict()

    def do_fetch_log(self, path: str, tail: int = 200) -> dict[str, Any]:
        """Read the tail of a remote log without needing a whole operation."""
        self.session.touch()
        command = tail_command(path, int(tail), windows=self.session.host.is_windows)
        return self.engine.run_command(command, timeout_s=180).to_dict()

    def do_upload(self, local_path: str, remote_path: str) -> dict[str, Any]:
        self.session.touch()
        self.session.upload(local_path, remote_path)
        if self.session.audit:
            self.session.audit.action(
                "FILE_UPLOAD",
                target=self.session.host_id,
                detail=f"{local_path} -> {remote_path}",
                local=local_path,
                remote=remote_path,
            )
        return {"uploaded": remote_path}

    def do_download(self, remote_path: str, local_path: str) -> dict[str, Any]:
        self.session.touch()
        self.session.fetch(remote_path, local_path)
        if self.session.audit:
            self.session.audit.action(
                "FILE_DOWNLOAD",
                source=self.session.host_id,
                target="local",
                detail=f"{remote_path} -> {local_path}",
                local=local_path,
                remote=remote_path,
            )
        return {"downloaded": local_path}

    def do_open_tunnel(
        self, dest_host: str, dest_port: int, purpose: str = "", local_port: int = 0
    ) -> dict[str, Any]:
        """Forward a local port through the chain (used by ``ac rdp``/``ac shell``/``ac tunnel``)."""
        self.session.touch()
        tunnel = self.session.open_tunnel(
            dest_host, int(dest_port), purpose=purpose, local_port=int(local_port)
        )
        with self._lock:
            tunnel_id = self._next_tunnel_id
            self._next_tunnel_id += 1
            self._tunnels[tunnel_id] = tunnel
        return {
            "tunnel_id": tunnel_id,
            "local_host": "127.0.0.1",
            "local_port": tunnel.local_port,
            "dest": f"{dest_host}:{dest_port}",
        }

    def do_close_tunnel(self, tunnel_id: int) -> dict[str, Any]:
        with self._lock:
            tunnel = self._tunnels.pop(int(tunnel_id), None)
        if tunnel is not None:
            tunnel.stop()
        return {"closed": tunnel_id}

    def do_credentials_for(self, node_id: str) -> dict[str, Any]:
        """Username only.  Passwords never cross this socket.

        ``ac rdp`` uses this to pre-fill the username in the .rdp file; the
        password is typed into ``mstsc``'s own prompt.
        """
        cred = self.session.creds.peek(node_id)
        return {"node_id": node_id, "username": cred.username if cred else None}

    def do_close(self, status: str = "closed") -> dict[str, Any]:
        """Report first, tear down second.

        Shutting down inside the handler races the reply: the listener closes
        while the report is still in flight, and whoever typed `ac disconnect`
        gets a connection error instead of the status they are owed. The actual
        teardown is deferred until after the reply has been written.
        """
        report = self.session.status()
        report["closing"] = True
        report["status"] = status
        self._close_after_reply = True
        return report

    def _trigger_stop(self) -> None:
        """Stop the accept loop, nudging it out of its timeout."""
        self._stop.set()
        try:
            if self._socket is not None:
                with socket.create_connection(
                    ("127.0.0.1", self._socket.getsockname()[1]), timeout=2
                ):
                    pass
        except OSError:
            pass


# --------------------------------------------------------------------------
# Building sessions
# --------------------------------------------------------------------------


def build_session(
    host_id: str,
    *,
    inventory: Inventory | None = None,
    catalog: Catalog | None = None,
    allowed_operations: tuple[str, ...] = (),
    idle_timeout_s: int | None = None,
    agent_id: str | None = None,
    prompter_name: str | None = None,
    fallback_to_hop: bool = True,
    gatekeeper: "Gatekeeper | None" = None,
) -> Session:
    """Construct (but do not connect) a session for ``host_id``.

    ``gatekeeper`` plugs an external governance plane in: its ``receipt`` sink
    mirrors every canonical audit action. None (the default) keeps today's
    behaviour exactly.
    """
    if inventory is None or catalog is None:
        loaded_inventory, loaded_catalog, _warnings = load_all()
        inventory = inventory or loaded_inventory
        catalog = catalog or loaded_catalog

    # A distinct identity per run. A single static agent id makes concurrent
    # executions indistinguishable in the trail, which is precisely when telling
    # them apart matters.
    identity = AgentIdentity.create(
        prefix=inventory.agent_prefix,
        session_prefix=inventory.session_prefix,
        agent_id=agent_id,
    )

    log_config = inventory.logging
    directory = log_config.resolve_directory()
    log_config.prune(directory)

    audit = AuditLog(
        session_id=identity.session_id,
        agent_id=identity.agent_id,
        host_id=host_id,
        directory=directory,
        trace_id=identity.trace_id,
        enabled=log_config.enabled,
        sink=gatekeeper.receipt if gatekeeper is not None else None,
    )

    session = Session(
        inventory=inventory,
        catalog=catalog,
        host_id=host_id,
        agent_id=identity.agent_id,
        session_id=identity.session_id,
        creds=CredentialStore(prompter=select_prompter(prompter_name)),
        audit=audit,
        gatekeeper=gatekeeper,
        allowed_operations=allowed_operations,
        fallback_to_hop=fallback_to_hop,
    )
    if idle_timeout_s is not None:
        session.idle_timeout_s = idle_timeout_s
    return session


class EphemeralSession:
    """A session built, used, and torn down inside a single command.

    The fallback when no daemon is running.  Every hop prompts again -- through
    the Windows credential dialog if there is no terminal -- so it is fine for a
    one-shot query and painful for a twenty-step operation.  Callers should
    recommend ``ac connect`` when they end up here.
    """

    def __init__(self, host_id: str, **kwargs: Any) -> None:
        self.host_id = host_id
        # No hop fallback here. A degraded session is something an operator
        # decides what to do with at a prompt; a one-shot command that silently
        # ran somewhere other than where it was aimed would be a lie.
        kwargs.setdefault("fallback_to_hop", False)
        self._kwargs = kwargs
        self.session: Session | None = None

    def __enter__(self) -> Session:
        self.session = build_session(self.host_id, **self._kwargs).connect()
        return self.session

    def __exit__(self, exc_type: type[BaseException] | None, *_rest: object) -> None:
        if self.session is not None:
            self.session.close(status="error" if exc_type else "closed")
            self.session = None
