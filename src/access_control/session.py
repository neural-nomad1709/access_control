"""A live, authenticated path to one host.

Building the chain is expensive -- every hop prompts the operator for a password
-- so a session is built once and held open for the whole task.  PLAN.md is
explicit that "the active window/session should live until task finishes and
status must be shared with user prior session disconnection", which is what
:meth:`Session.close` does.

What a session owns, in order:

1. SSH hops, each reached through the one before it.
2. A loopback tunnel anchored at the last SSH hop.
3. A PSRP channel to the first Windows machine over that tunnel.
4. If the target sits behind a Windows jump server, a nested channel through it.

Everything is torn down in reverse on close, and credentials are wiped.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog, default_agent_id, new_session_id
from .config import Catalog, Host, Inventory, Node
from .credentials import CredentialStore
from .errors import ChannelUnavailable, ConnectionFailed, SessionError
from .redact import clear as clear_secrets
from .route import CHANNEL_NESTED_WINRM, CHANNEL_SSH, CHANNEL_WINRM, Route, plan_route
from .transport.base import ExecResult
from .transport.ssh import SSHHop, connect_chain, connect_hop
from .transport.tunnel import LocalTunnel
from .transport.winrm import NestedWinRMChannel, WinRMChannel

DEFAULT_IDLE_TIMEOUT_S = 30 * 60


def _windows_label(node: Node, role: str) -> str:
    """The prompt an operator sees when this Windows machine asks for a password."""
    user = f"{node.user}@" if node.user else ""
    return f"{role} {node.description or node.id} [{user}{node.host}]"


@dataclass
class Session:
    """One authenticated path to one host, plus everything it owns."""

    inventory: Inventory
    catalog: Catalog
    host_id: str
    agent_id: str = field(default_factory=default_agent_id)
    session_id: str = field(default_factory=new_session_id)
    creds: CredentialStore = field(default_factory=CredentialStore)
    audit: AuditLog | None = None
    #: Operations the operator authorised for this session.  Empty means "any
    #: operation the catalog permits for this host".
    allowed_operations: tuple[str, ...] = ()
    idle_timeout_s: int = DEFAULT_IDLE_TIMEOUT_S
    #: When the last leg fails but the bastion chain stood up, hold the session
    #: at the last hop that did authenticate instead of tearing it all down.
    #: The passwords are already typed; throwing them away to make the operator
    #: retype them is the wrong answer to "the target refused".
    fallback_to_hop: bool = True

    def __post_init__(self) -> None:
        self.route: Route = plan_route(self.inventory, self.host_id)
        self.host: Host = self.route.host
        if self.audit is None:
            self.audit = AuditLog(
                session_id=self.session_id, agent_id=self.agent_id, host_id=self.host_id
            )
        self.ssh_hops: list[SSHHop] = []
        self.tunnels: list[LocalTunnel] = []
        self.winrm: WinRMChannel | None = None
        self.channel: Any = None
        self.connected_at: float | None = None
        self.last_used: float = time.time()
        self.closed = False
        self._close_reason: str | None = None
        #: Why the target leg failed, when the session fell back to a hop.
        self.degraded_reason: str | None = None
        #: The machine commands actually reach.  ``None`` means the target.
        self.active_node: Node | None = None

    # -- lifecycle --------------------------------------------------------

    def connect(self) -> "Session":
        """Walk the declared route, prompting for each hop's credentials in turn."""
        if self.channel is not None:
            return self

        assert self.audit is not None
        self.audit.open_session(
            host_id=self.host_id,
            route=self.route.describe(),
            hops=self.route.hop_labels(),
            allowed_operations=list(self.allowed_operations),
        )

        # Stage 1: the bastion chain.  Nothing to fall back to if this fails --
        # there is no authenticated machine to hold the session at.
        try:
            ssh_legs = self.route.ssh_legs
            if self.route.channel == CHANNEL_SSH:
                ssh_legs = ssh_legs[:-1]  # the target itself is connected below
            if ssh_legs:
                self.ssh_hops = connect_chain(
                    [leg.node for leg in ssh_legs],
                    self.creds,
                    audit=self.audit,
                    endpoints=[leg.endpoint for leg in ssh_legs],
                )
        except BaseException as exc:
            self.audit.error(f"connect failed: {exc}", host_id=self.host_id)
            self.close(status="connect-failed", wipe_credentials=True)
            raise

        # Stage 2: the target.  If this fails and a hop is standing, keep it.
        try:
            self.channel = self._open_target_channel()
        except BaseException as exc:
            if isinstance(exc, Exception) and self.fallback_to_hop and self.ssh_hops:
                self._degrade_to_hop(exc)
                return self
            self.audit.error(f"connect failed: {exc}", host_id=self.host_id)
            self.close(status="connect-failed", wipe_credentials=True)
            raise

        self.connected_at = time.time()
        self.touch()
        return self

    def _open_target_channel(self) -> Any:
        """Build the final leg, whichever of the three shapes this route is."""
        if self.route.channel == CHANNEL_SSH:
            return self._connect_ssh_target()
        if self.route.channel == CHANNEL_WINRM:
            return self._connect_winrm(self.host, role="Target")
        if self.route.channel == CHANNEL_NESTED_WINRM:
            jump = self.route.windows_hops[0]
            # A retry after falling back to the jump must not re-authenticate
            # it; that leg is already up and would cost another password.
            if self.winrm is None:
                self.winrm = self._connect_winrm(jump, role="Jump server")
            return self._connect_nested(jump)
        raise SessionError(f"unsupported channel '{self.route.channel}'")

    def _degrade_to_hop(self, exc: BaseException) -> None:
        """Hold the session open at the last hop that did authenticate.

        The operator keeps a shell on the bastion -- which is where the useful
        diagnosis lives, since it is the machine that was supposed to reach the
        target -- without retyping a password.  Commands run here go to the
        *bastion*, so :meth:`exec` refuses them unless the caller says it knows
        that, and no catalog operation is offered at all.
        """
        # A nested-WinRM route that got as far as the jump server holds there
        # rather than dropping all the way back to the bastion: the jump is the
        # machine one leg from the target, and it is already authenticated.
        if self.winrm is not None:
            hop_id, hop_node, channel = (
                self.winrm.node_id,
                self.route.windows_hops[0],
                self.winrm,
            )
        else:
            hop = self.ssh_hops[-1]
            hop_id, hop_node, channel = hop.node_id, hop.node, hop

        self.degraded_reason = str(exc)
        self.active_node = hop_node
        self.channel = channel
        self.connected_at = time.time()
        self.touch()
        assert self.audit is not None
        self.audit.error(f"target leg failed: {exc}", host_id=self.host_id)
        self.audit.emit(
            "session.degraded",
            host_id=self.host_id,
            held_at=hop_id,
            reason=str(exc),
            note="the bastion chain is up; the target leg is not",
        )

    def retry_target(self) -> bool:
        """Re-attempt the failed final leg over the hops already authenticated.

        Returns ``True`` once the session is on the real target.  On failure the
        session stays degraded and :attr:`degraded_reason` is updated, so this
        can be called repeatedly while the operator fixes the far end.
        """
        if not self.degraded:
            return True
        try:
            channel = self._open_target_channel()
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            self.degraded_reason = str(exc)
            assert self.audit is not None
            self.audit.error(f"target retry failed: {exc}", host_id=self.host_id)
            return False
        self.channel = channel
        self.degraded_reason = None
        self.active_node = None
        self.connected_at = time.time()
        self.touch()
        assert self.audit is not None
        self.audit.emit("session.recovered", host_id=self.host_id)
        return True

    def _connect_ssh_target(self) -> SSHHop:
        """Final SSH leg to a Linux/Unix/AIX target (or Windows OpenSSH)."""
        leg = self.route.final_leg
        hop = connect_hop(
            self.host,
            self.creds,
            via=self.ssh_hops[-1] if self.ssh_hops else None,
            audit=self.audit,
            endpoint=leg.endpoint,
        )
        self.ssh_hops.append(hop)
        return hop

    def _connect_winrm(self, node: Node, *, role: str) -> WinRMChannel:
        """Reach ``node``'s WinRM endpoint and authenticate PowerShell Remoting.

        The endpoint comes from the declared route, so an address that differs by
        vantage point is honoured. If it is a pre-established tunnel
        (``localhost:44001``), we connect to it as-is rather than building a
        second forward on top of one that already exists.
        """
        leg = self.route.leg_for(node.id)
        endpoint = leg.endpoint if leg else None
        if endpoint is None:  # pragma: no cover - plan_route guarantees a leg
            raise SessionError(f"no declared endpoint for '{node.id}'")

        assert self.audit is not None

        #: The forward we built for this leg, if any. Holds the reason a
        #: forwarded connection died, which the client only ever sees as a reset.
        active_tunnel: LocalTunnel | None = None

        if endpoint.preestablished:
            connect_host, connect_port = endpoint.hostname, endpoint.port
            self.audit.emit(
                "tunnel.preestablished",
                hop_id=node.id,
                endpoint=f"{endpoint.hostname}:{endpoint.port}",
                note="using a forward declared in inventory.yaml; none was created",
            )
        else:
            origin = self.ssh_hops[-1] if self.ssh_hops else None
            if origin is None:
                # Direct WinRM: the route begins at `local` with the target's
                # real address (VPN / same network segment). There is no SSH hop
                # to tunnel through, so connect straight to the declared endpoint.
                # This is not a *discovered* direct connection -- it only happens
                # for an explicit `via: from: local` edge the resolver returned,
                # so the "declared, never guessed" rule still holds. Recorded as
                # its own audit event because it bypasses every bastion.
                connect_host, connect_port = endpoint.hostname, endpoint.port
                self.audit.emit(
                    "winrm.direct",
                    hop_id=node.id,
                    endpoint=f"{endpoint.hostname}:{endpoint.port}",
                    note="direct WinRM from local; no bastion tunnel was built",
                )
            else:
                active_tunnel = tunnel = LocalTunnel(origin, endpoint.hostname, endpoint.port)
                tunnel.start()
                self.tunnels.append(tunnel)
                connect_host, connect_port = "127.0.0.1", int(tunnel.local_port or 0)
                self.audit.emit(
                    "tunnel.open",
                    hop_id=origin.node_id,
                    target=f"{endpoint.hostname}:{endpoint.port}",
                    local_port=tunnel.local_port,
                    purpose=f"winrm:{node.id}",
                )

        label = _windows_label(node, role)
        cred = self.creds.acquire(
            node.id,
            label=label,
            username=node.qualified_user,
            need_password=True,
            prompt_username=node.auth.prompt_username or not node.user,
            domain=node.domain,
        )
        if not cred.username:
            raise ConnectionFailed(
                f"{label}: no username configured. Set 'username' for this node in "
                f"inventory.yaml, and 'domain' if it is domain-joined -- WinRM needs "
                f"DOMAIN\\user against a domain-joined host."
            )

        # Resolve 'auto' from the route this leg actually took: a direct
        # (no-tunnel) hop needs the pure-Python NTLM provider to get past a local
        # "Restrict NTLM outgoing" policy; a tunnelled/loopback hop uses SSPI,
        # which that policy does not block. Each server's own `via:` decides,
        # so a large fleet needs no per-host tuning.
        ntlm_provider = node.auth.ntlm_provider
        if ntlm_provider == "auto":
            direct = active_tunnel is None and not endpoint.preestablished
            ntlm_provider = "python" if direct else "sspi"
        self.audit.emit(
            "winrm.ntlm_provider",
            hop_id=node.id,
            provider=ntlm_provider,
            configured=node.auth.ntlm_provider,
        )

        channel = WinRMChannel(
            node.id,
            connect_host,
            connect_port,
            username=cred.username,
            password=cred.password or "",
            auth=node.auth.transport,
            ntlm_provider=ntlm_provider,
            display_target=f"{endpoint.hostname}:{endpoint.port}",
        )
        started = time.monotonic()
        try:
            channel.connect()
        except Exception as exc:
            # The password was wrong or the host is unreachable; drop it so the
            # operator is prompted again rather than retrying a bad credential.
            self.creds.discard(node.id)
            # The tunnel records why each forwarded connection died, and that is
            # the only place the real reason exists: a channel the bastion
            # refused to open is reported to the client as a plain connection
            # reset, which says nothing about whose fault it was. Surface it.
            reasons = list(active_tunnel.errors) if active_tunnel is not None else []
            if reasons:
                unique = list(dict.fromkeys(reasons))
                raise ConnectionFailed(
                    f"{exc}\n\nWHAT THE BASTION ACTUALLY SAID when asked to forward to "
                    f"{endpoint.hostname}:{endpoint.port}:\n"
                    + "\n".join(f"    {reason}" for reason in unique[:3])
                    + "\n'connect failed' means the bastion could not reach that address -- "
                    "a firewall or a wrong address, not a WinRM problem. "
                    "'administratively prohibited' means the bastion refuses forwarding, "
                    "which needs its owner."
                ) from exc
            raise
        self.audit.action(
            "WINRM_CONNECT",
            source=self.ssh_hops[-1].node_id if self.ssh_hops else "local",
            target=node.id,
            result="SUCCESS",
            hop_id=node.id,
            endpoint=f"{endpoint.hostname}:{endpoint.port}",
            channel="winrm",
            username=cred.username,
            domain=node.domain,
            context=node.context.to_dict(),
            duration_s=round(time.monotonic() - started, 2),
        )
        self.creds.note_authenticated(node.id)
        return channel

    def _connect_nested(self, jump: Node) -> NestedWinRMChannel:
        """The Windows jump server → Windows target leg."""
        assert self.winrm is not None
        leg = self.route.final_leg
        label = _windows_label(self.host, "Target")
        cred = self.creds.acquire(
            self.host.id,
            label=label,
            username=self.host.qualified_user,
            need_password=True,
            prompt_username=self.host.auth.prompt_username or not self.host.user,
            domain=self.host.domain,
        )
        if not cred.username:
            raise ConnectionFailed(
                f"{label}: no username configured. Set 'username' (and 'domain' if it is "
                f"domain-joined) for this host in inventory.yaml."
            )

        channel = NestedWinRMChannel(
            self.host.id,
            self.winrm,
            target_host=leg.endpoint.hostname,
            target_port=leg.endpoint.port,
            username=cred.username,
            password=cred.password or "",
        )
        started = time.monotonic()
        try:
            channel.connect()
        except Exception:
            self.creds.discard(self.host.id)
            raise
        assert self.audit is not None
        self.audit.action(
            "WINRM_CONNECT",
            source=jump.id,
            target=self.host.id,
            result="SUCCESS",
            hop_id=self.host.id,
            endpoint=f"{leg.endpoint.hostname}:{leg.endpoint.port}",
            channel="nested-winrm",
            username=cred.username,
            domain=self.host.domain,
            context=self.host.context.to_dict(),
            duration_s=round(time.monotonic() - started, 2),
        )
        self.creds.note_authenticated(self.host.id)
        return channel

    # -- use --------------------------------------------------------------

    def touch(self) -> None:
        self.last_used = time.time()

    @property
    def degraded(self) -> bool:
        """True when the session is held at a hop, not on the target."""
        return self.degraded_reason is not None

    @property
    def current_node(self) -> Node:
        """The machine commands actually reach right now."""
        return self.active_node or self.host

    @property
    def prompt_label(self) -> str:
        """``user@address`` for the machine this session is currently on."""
        node = self.current_node
        user = node.qualified_user or node.user or ""
        return f"{user}@{node.host}" if user else node.host

    @property
    def idle_s(self) -> float:
        return time.time() - self.last_used

    @property
    def expired(self) -> bool:
        return self.idle_timeout_s > 0 and self.idle_s > self.idle_timeout_s

    @property
    def active(self) -> bool:
        if self.closed or self.channel is None:
            return False
        if self.expired:
            return False
        for hop in self.ssh_hops:
            if not hop.active:
                return False
        return True

    def require_active(self) -> None:
        if self.closed:
            raise SessionError(
                f"session {self.session_id} is closed ({self._close_reason or 'disconnected'})."
            )
        if self.channel is None:
            raise SessionError(f"session {self.session_id} is not connected")
        if self.expired:
            raise SessionError(
                f"session {self.session_id} has been idle for {int(self.idle_s / 60)} minutes "
                f"and has expired. Credentials were not stored -- reconnect with:\n"
                f"    uv run ac connect {self.host_id}"
            )
        for hop in self.ssh_hops:
            if not hop.active:
                raise SessionError(
                    f"the SSH connection to '{hop.node_id}' dropped. Reconnect with:\n"
                    f"    uv run ac connect {self.host_id}"
                )

    def exec(
        self,
        command: str,
        *,
        shell: str | None = None,
        timeout_s: int = 600,
        allow_degraded: bool = False,
    ) -> ExecResult:
        """Run one command on the target.  Policy is applied by the engine.

        A degraded session runs on a *hop*, not the target.  Callers that did
        not say they know that are refused, because an agent that believes it is
        on the application server and is actually on the bastion is exactly the
        failure this tool exists to prevent.
        """
        self.require_active()
        if self.degraded and not allow_degraded:
            raise SessionError(
                f"this session is held at '{self.current_node.id}' because the leg to "
                f"'{self.host_id}' failed:\n    {self.degraded_reason}\n"
                f"Commands here would run on the hop, not on {self.host_id}. Use the "
                f"prompt in the `ac connect` window to work on the hop, or fix the far "
                f"end and run :retry there."
            )
        self.touch()
        effective_shell = shell or self.default_shell
        result = self.channel.exec(command, shell=effective_shell, timeout_s=timeout_s)
        self.touch()
        return result

    @property
    def default_shell(self) -> str:
        return "powershell" if self.current_node.is_windows else "bash"

    def upload(self, local_path: str, remote_path: str) -> None:
        self.require_active()
        self.touch()
        uploader = getattr(self.channel, "upload", None)
        if uploader is None:
            raise ChannelUnavailable(f"{self.host_id}: this channel cannot upload files")
        uploader(local_path, remote_path)

    def fetch(self, remote_path: str, local_path: str) -> None:
        self.require_active()
        self.touch()
        fetcher = getattr(self.channel, "fetch", None)
        if fetcher is None:
            raise ChannelUnavailable(f"{self.host_id}: this channel cannot fetch files")
        fetcher(remote_path, local_path)

    def open_tunnel(
        self, dest_host: str, dest_port: int, purpose: str = "", local_port: int = 0
    ) -> LocalTunnel:
        """Forward a local port to ``dest_host:dest_port`` through the chain."""
        self.require_active()
        if not self.ssh_hops:
            raise SessionError(f"{self.host_id}: no SSH hop to anchor a tunnel at")
        tunnel = LocalTunnel(self.ssh_hops[-1], dest_host, dest_port, local_port=local_port)
        tunnel.start()
        self.tunnels.append(tunnel)
        if self.audit:
            self.audit.action(
                "TUNNEL_OPEN",
                source=self.ssh_hops[-1].node_id,
                target=f"{dest_host}:{dest_port}",
                detail=f"127.0.0.1:{tunnel.local_port} -> {dest_host}:{dest_port}",
                local_port=tunnel.local_port,
                purpose=purpose,
            )
        return tunnel

    # -- reporting --------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Everything ``ac status`` reports."""
        assert self.audit is not None
        summary = self.audit.summary()
        return {
            **summary,
            "host_id": self.host_id,
            "route": self.route.describe(),
            "hops": self.route.hop_labels(),
            "channel": self.route.channel,
            "degraded": self.degraded,
            "degraded_reason": self.degraded_reason,
            "current_node": self.current_node.id,
            "current_address": self.prompt_label,
            "connected": self.active,
            "closed": self.closed,
            "connected_at": self.connected_at,
            "idle_s": round(self.idle_s, 1),
            "idle_timeout_s": self.idle_timeout_s,
            "expires_in_s": (
                max(0, round(self.idle_timeout_s - self.idle_s)) if self.idle_timeout_s else None
            ),
            "allowed_operations": list(self.allowed_operations),
            "authenticated_nodes": self.creds.known(),
            "tunnels": [
                {"local": t.endpoint, "to": f"{t.dest_host}:{t.dest_port}", "active": t.active}
                for t in self.tunnels
            ],
        }

    def operations(self) -> list[dict[str, Any]]:
        """Operations this session may run, honouring the per-session allow-list."""
        if self.degraded:
            # Every operation in the catalog is written against the target. None
            # of them is meaningful on the hop we are held at.
            return []
        available = self.catalog.for_host(self.host)
        if self.allowed_operations:
            available = [op for op in available if op.id in self.allowed_operations]
        return [
            {
                "id": op.id,
                "description": op.description,
                "params": [
                    {
                        "name": p.name,
                        "required": p.required,
                        "default": p.default,
                        "description": p.description,
                    }
                    for p in op.params
                ],
                "steps": [{"id": s.id, "desc": s.desc} for s in op.steps],
                "requires_permission": op.is_gated,
                "destructive": op.destructive,
            }
            for op in available
        ]

    def permits(self, operation_id: str) -> bool:
        if self.degraded:
            return False
        return not self.allowed_operations or operation_id in self.allowed_operations

    # -- teardown ---------------------------------------------------------

    def close(self, status: str = "closed", *, wipe_credentials: bool = True) -> dict[str, Any]:
        """Tear everything down in reverse and report before the path is gone."""
        if self.closed:
            return self.status()

        self._close_reason = status
        report = self.status()

        for tunnel in reversed(self.tunnels):
            try:
                tunnel.stop()
            except Exception:  # noqa: BLE001 - teardown must complete
                pass
        self.tunnels.clear()

        if self.winrm is not None:
            self.winrm.close()
            self.winrm = None
        if isinstance(self.channel, WinRMChannel):
            self.channel.close()
        self.channel = None

        for hop in reversed(self.ssh_hops):
            try:
                hop.close()
            except Exception:  # noqa: BLE001
                pass
        self.ssh_hops.clear()

        if wipe_credentials:
            self.creds.clear()
            clear_secrets()

        self.closed = True
        if self.audit is not None:
            summary_path = self.audit.close(status=status)
            report["summary_file"] = str(summary_path)
        report["closed"] = True
        report["status"] = status
        return report

    def __enter__(self) -> "Session":
        return self.connect()

    def __exit__(self, exc_type: type[BaseException] | None, *_rest: object) -> None:
        self.close(status="error" if exc_type else "closed")
