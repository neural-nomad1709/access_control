"""Explicit connectivity graph and route resolution.

Enterprise networks are segmented, and which machine can reach which is a fact
about firewall rules and jump-host policy -- not something to infer.  So the
graph here is built **only from declared edges**.  Resolution searches those
declarations; it never probes the network, never guesses, and never falls back
to a direct connection when the hierarchy is missing.

    local -> bastion1 -> JumpServer01 -> linux-app01

Each edge carries how the target is addressed *from that source*, because the
same machine is reached differently depending on where you are standing.  A jump
server might be ``10.20.4.11:3389`` from the bastion and ``localhost:44001`` on
the operator's laptop, where an SSH tunnel already terminates.

Failing fast is deliberate.  A missing edge produces an error naming what is
missing, rather than a connection attempt that times out somewhere unhelpful.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .context import NetworkContext
from .errors import ConfigError, RouteError

#: The operator's own machine -- the implicit start of every route.
LOCAL = "local"

PROTOCOLS = frozenset({"ssh", "rdp", "winrm", "winrm-ssl", "wmi"})

#: Protocols that can carry commands. RDP cannot: it moves pixels, so it can
#: never be an automation protocol however it is configured.
AUTOMATION_PROTOCOLS = frozenset({"ssh", "winrm", "winrm-ssl", "wmi"})

DEFAULT_PORTS = {"ssh": 22, "rdp": 3389, "winrm": 5985, "winrm-ssl": 5986, "wmi": 135}


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    """A concrete address:port and protocol for one leg of a route."""

    hostname: str
    port: int
    protocol: str
    #: True when ``hostname``/``port`` is a forward that already exists on the
    #: client (an mRemoteNG-style SSH tunnel), so we must not build our own.
    preestablished: bool = False

    def __str__(self) -> str:
        suffix = " (pre-established tunnel)" if self.preestablished else ""
        return f"{self.hostname}:{self.port}/{self.protocol}{suffix}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "protocol": self.protocol,
            "preestablished": self.preestablished,
        }

    @classmethod
    def parse(cls, raw: Any, where: str, *, require_port: bool = True) -> "Endpoint":
        if raw is None:
            raise ConfigError(f"{where}: missing endpoint definition")
        if not isinstance(raw, Mapping):
            raise ConfigError(f"{where}: expected a mapping with hostname, port, protocol")
        data = dict(raw)

        protocol = str(data.get("protocol", "")).lower()
        if not protocol:
            raise ConfigError(f"{where}.protocol: required (one of {sorted(PROTOCOLS)})")
        if protocol not in PROTOCOLS:
            raise ConfigError(
                f"{where}.protocol: '{protocol}' is not one of {sorted(PROTOCOLS)}"
            )

        hostname = str(data.get("hostname", data.get("host", ""))).strip()
        if not hostname:
            raise ConfigError(f"{where}.hostname: required")

        if "port" not in data or data["port"] in (None, ""):
            if require_port:
                # Defaulting a port is how a connection silently goes to the
                # wrong place, or retries against an endpoint that was never
                # listening. Declare it.
                raise ConfigError(
                    f"{where}.port: required. Ports are mandatory on every hop -- "
                    f"the default for {protocol} would be {DEFAULT_PORTS.get(protocol, '?')}, "
                    f"but state it explicitly."
                )
            port = DEFAULT_PORTS[protocol]
        else:
            try:
                port = int(data["port"])
            except (TypeError, ValueError):
                raise ConfigError(f"{where}.port: '{data['port']}' is not a number") from None
        if not 1 <= port <= 65535:
            raise ConfigError(f"{where}.port: {port} is outside 1-65535")

        preestablished = bool(data.get("preestablished", data.get("tunnel_preestablished", False)))
        if hostname.lower() in ("localhost", "127.0.0.1", "::1") and not preestablished:
            # A loopback address on an edge can only mean a forward that already
            # exists; treating it as a real host would connect to the operator's
            # own machine.
            preestablished = True

        return cls(hostname=hostname, port=port, protocol=protocol, preestablished=preestablished)


# --------------------------------------------------------------------------
# Edges
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RouteEdge:
    """A declared, permitted hop from ``source`` to ``target``."""

    source: str
    target: str
    #: How commands are run on the target from here. None means this leg is
    #: interactive-only (a human at an RDP session).
    automation: Endpoint | None = None
    #: How a human reaches the target from here, if at all.
    interactive: Endpoint | None = None
    domain: str = ""
    username: str | None = None
    description: str = ""

    @property
    def primary(self) -> Endpoint:
        endpoint = self.automation or self.interactive
        if endpoint is None:  # pragma: no cover - parse() forbids this
            raise RouteError(f"edge {self.source} -> {self.target} declares no endpoint")
        return endpoint

    @property
    def automatable(self) -> bool:
        return self.automation is not None

    def describe(self) -> str:
        parts = [f"{self.source} -> {self.target}"]
        if self.automation:
            parts.append(f"automation {self.automation}")
        if self.interactive:
            parts.append(f"interactive {self.interactive}")
        return "  ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "automation": self.automation.to_dict() if self.automation else None,
            "interactive": self.interactive.to_dict() if self.interactive else None,
            "domain": self.domain,
            "username": self.username,
            "description": self.description,
        }

    @classmethod
    def parse(cls, raw: Any, where: str) -> "RouteEdge":
        if not isinstance(raw, Mapping):
            raise ConfigError(f"{where}: expected a mapping with source and target")
        data = dict(raw)
        source = str(data.get("source", "")).strip()
        target = str(data.get("target", "")).strip()
        if not source:
            raise ConfigError(f"{where}.source: required (use '{LOCAL}' for the operator's machine)")
        if not target:
            raise ConfigError(f"{where}.target: required")
        if source == target:
            raise ConfigError(f"{where}: source and target are both '{source}'")

        automation_raw = data.get("automation")
        interactive_raw = data.get("interactive")

        # Shorthand: a bare hostname/port/protocol on the edge itself. Whether
        # it is the automation or the interactive endpoint follows from the
        # protocol, since RDP can never carry commands.
        if automation_raw is None and interactive_raw is None:
            inline = {k: data[k] for k in ("hostname", "host", "port", "protocol") if k in data}
            if "preestablished" in data:
                inline["preestablished"] = data["preestablished"]
            if not inline:
                raise ConfigError(
                    f"{where}: declare how '{target}' is reached from '{source}' -- either "
                    f"hostname/port/protocol directly on the edge, or an 'automation' "
                    f"and/or 'interactive' block."
                )
            endpoint = Endpoint.parse(inline, where)
            if endpoint.protocol in AUTOMATION_PROTOCOLS:
                automation, interactive = endpoint, None
            else:
                automation, interactive = None, endpoint
        else:
            automation = (
                Endpoint.parse(automation_raw, f"{where}.automation")
                if automation_raw is not None
                else None
            )
            interactive = (
                Endpoint.parse(interactive_raw, f"{where}.interactive")
                if interactive_raw is not None
                else None
            )

        if automation is not None and automation.protocol not in AUTOMATION_PROTOCOLS:
            raise ConfigError(
                f"{where}.automation.protocol: '{automation.protocol}' cannot run commands. "
                f"RDP carries pixels, not exit codes -- declare it under 'interactive' and "
                f"give automation one of {sorted(AUTOMATION_PROTOCOLS)}."
            )

        return cls(
            source=source,
            target=target,
            automation=automation,
            interactive=interactive,
            domain=str(data.get("domain", "")),
            username=(str(data["username"]) if data.get("username") else None),
            description=str(data.get("description", "")),
        )


# --------------------------------------------------------------------------
# The graph
# --------------------------------------------------------------------------


CHANNEL_SSH = "ssh"
CHANNEL_WINRM = "winrm"
CHANNEL_NESTED_WINRM = "nested-winrm"

SSH_PROTOCOLS = frozenset({"ssh"})
WINRM_PROTOCOLS = frozenset({"winrm", "winrm-ssl"})


def classify_chain(target: str, edges: Sequence[RouteEdge]) -> str:
    """Work out the execution shape of a declared chain, or reject it.

    Runs at *load* time as well as connect time, so an untraversable topology is
    an error the moment the config is read rather than a surprise halfway
    through a run. Operates on protocols alone, so it needs nothing from the
    node registry.
    """
    protocols = [edge.primary.protocol for edge in edges]
    names = [edge.target for edge in edges]

    seen_winrm = False
    for protocol, name in zip(protocols, names):
        if protocol in WINRM_PROTOCOLS:
            seen_winrm = True
        elif protocol in SSH_PROTOCOLS and seen_winrm:
            raise RouteError(
                f"route to '{target}': SSH leg to '{name}' comes after a Windows (WinRM) "
                f"hop. Chaining back to SSH from a Windows jump server is not supported -- "
                f"order the route so SSH bastions come first."
            )
        elif protocol not in SSH_PROTOCOLS and protocol not in WINRM_PROTOCOLS:
            raise RouteError(
                f"route to '{target}': leg to '{name}' uses protocol '{protocol}', which "
                f"cannot carry commands. Declare an 'automation' endpoint for that hop."
            )

    intermediate = [
        name
        for protocol, name in zip(protocols[:-1], names[:-1])
        if protocol in WINRM_PROTOCOLS
    ]
    if len(intermediate) > 1:
        raise RouteError(
            f"route to '{target}': {len(intermediate)} Windows jump servers "
            f"({', '.join(intermediate)}). Only one is supported -- each "
            f"Windows-to-Windows leg is an Invoke-Command run by the hop before it, and "
            f"nesting those more than one deep means passing a credential through an "
            f"intermediate script. Reach the extra jump server as a target in its own "
            f"right, or route around it."
        )

    if protocols[-1] in SSH_PROTOCOLS:
        if intermediate:
            raise RouteError(
                f"route to '{target}': an SSH target cannot be reached through the Windows "
                f"jump server '{intermediate[0]}'. Route it through SSH hops instead."
            )
        return CHANNEL_SSH
    return CHANNEL_NESTED_WINRM if intermediate else CHANNEL_WINRM


@dataclass(frozen=True)
class ResolvedRoute:
    """A validated, executable chain of declared edges."""

    target: str
    edges: tuple[RouteEdge, ...]
    warnings: tuple[str, ...] = ()

    @property
    def nodes(self) -> tuple[str, ...]:
        return (LOCAL, *(edge.target for edge in self.edges))

    @property
    def hops(self) -> tuple[str, ...]:
        """Every node between the operator and the target, exclusive."""
        return tuple(edge.target for edge in self.edges[:-1])

    @property
    def final(self) -> RouteEdge:
        return self.edges[-1]

    def describe(self) -> str:
        return " -> ".join(self.nodes)

    def describe_verbose(self) -> str:
        lines = [LOCAL]
        for edge in self.edges:
            endpoint = edge.primary
            lines.append(f"  -> {edge.target}  [{endpoint}]")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "path": list(self.nodes),
            "edges": [edge.to_dict() for edge in self.edges],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class RouteGraph:
    """All declared connectivity, and nothing else."""

    edges: tuple[RouteEdge, ...] = ()
    contexts: Mapping[str, NetworkContext] = field(default_factory=dict)
    #: Node ids that may be reached without traversing the graph. Only nodes
    #: explicitly marked so; never inferred.
    direct_allowed: frozenset[str] = frozenset()

    def outgoing(self, source: str) -> list[RouteEdge]:
        return [edge for edge in self.edges if edge.source == source]

    def incoming(self, target: str) -> list[RouteEdge]:
        return [edge for edge in self.edges if edge.target == target]

    @property
    def nodes(self) -> set[str]:
        names: set[str] = set()
        for edge in self.edges:
            names.add(edge.source)
            names.add(edge.target)
        names.discard(LOCAL)
        return names

    def entry_points(self) -> list[str]:
        """Nodes reachable straight from the operator's machine."""
        return [edge.target for edge in self.outgoing(LOCAL)]

    # -- resolution -------------------------------------------------------

    def resolve(self, target: str, *, require_automation: bool = True) -> ResolvedRoute:
        """Find the declared path from ``local`` to ``target``.

        Breadth-first over declared edges only, so the shortest declared route
        wins.  Raises rather than falling back to anything.
        """
        if target == LOCAL:
            raise RouteError(f"'{LOCAL}' is the operator's machine, not a target")

        if not self.incoming(target):
            known = ", ".join(sorted(self.nodes)) or "(none)"
            raise RouteError(
                f"ERROR: No route defined between requested target and available bastion.\n"
                f"  requested target : {target}\n"
                f"  reason           : no declared edge reaches it\n"
                f"  known nodes      : {known}\n"
                f"Declare the hop explicitly in inventory.yaml under 'routes:', for example:\n"
                f"  - source: <bastion or jump server>\n"
                f"    target: {target}\n"
                f"    hostname: <address as seen from the source>\n"
                f"    port: <explicit port>\n"
                f"    protocol: ssh|winrm|rdp\n"
                f"Routes are never discovered; a direct connection will not be attempted."
            )

        paths = self._shortest_paths(target)
        if not paths:
            entries = ", ".join(self.entry_points()) or "(none declared)"
            raise RouteError(
                f"ERROR: No route defined between requested target and available bastion.\n"
                f"  requested target : {target}\n"
                f"  reason           : '{target}' is declared, but no chain of edges connects "
                f"it back to '{LOCAL}'\n"
                f"  entry points     : {entries}\n"
                f"Add the missing link, starting from an entry point declared as "
                f"'source: {LOCAL}'."
            )

        if len(paths) > 1:
            rendered = "\n".join(
                "  " + " -> ".join([LOCAL, *(e.target for e in path)]) for path in paths
            )
            raise RouteError(
                f"ambiguous route to '{target}': {len(paths)} declared paths of equal length.\n"
                f"{rendered}\n"
                f"Traversal must be unambiguous -- remove an edge, or split the target into "
                f"separate entries per environment."
            )

        edges = paths[0]
        warnings = self._validate(target, edges, require_automation=require_automation)
        return ResolvedRoute(target=target, edges=tuple(edges), warnings=tuple(warnings))

    def _shortest_paths(self, target: str) -> list[list[RouteEdge]]:
        """All shortest declared paths from LOCAL to target (usually one)."""
        queue: deque[tuple[str, list[RouteEdge]]] = deque([(LOCAL, [])])
        seen_depth: dict[str, int] = {LOCAL: 0}
        found: list[list[RouteEdge]] = []
        best: int | None = None

        while queue:
            node, path = queue.popleft()
            if best is not None and len(path) >= best:
                continue
            for edge in self.outgoing(node):
                if any(e.target == edge.target for e in path) or edge.target == LOCAL:
                    continue  # no cycles
                extended = [*path, edge]
                if edge.target == target:
                    if best is None or len(extended) < best:
                        best, found = len(extended), [extended]
                    elif len(extended) == best:
                        found.append(extended)
                    continue
                depth = seen_depth.get(edge.target)
                if depth is None or depth >= len(extended):
                    seen_depth[edge.target] = len(extended)
                    queue.append((edge.target, extended))
        return found

    def _validate(
        self, target: str, edges: Sequence[RouteEdge], *, require_automation: bool
    ) -> list[str]:
        """Check the resolved path before anything is connected."""
        warnings: list[str] = []

        if require_automation and not edges[-1].automatable:
            interactive = edges[-1].interactive
            raise RouteError(
                f"'{target}' has no automation endpoint on its final hop "
                f"({edges[-1].source} -> {target}); it is declared "
                f"{'as ' + interactive.protocol + '-only' if interactive else 'with no protocol'}.\n"
                f"RDP cannot run commands. Either add an 'automation' block to that route "
                f"(winrm on Windows, ssh on Unix), or use 'ac rdp {target}' for an "
                f"interactive session."
            )

        for edge in edges[:-1]:
            if not edge.automatable and not edge.interactive:
                raise RouteError(
                    f"intermediate hop '{edge.target}' declares no usable endpoint"
                )
            if not edge.automatable:
                raise RouteError(
                    f"intermediate hop '{edge.target}' is declared "
                    f"{edge.interactive.protocol if edge.interactive else 'interactive'}-only, "
                    f"but a route passes through it to '{target}'.\n"
                    f"A hop has to run commands for the next leg to be launched from it. Give "
                    f"'{edge.source} -> {edge.target}' an 'automation' endpoint (winrm on "
                    f"Windows, ssh on Unix), or route around it."
                )

        if require_automation:
            classify_chain(target, edges)

        # Compliance boundary: crossing environments must be deliberate.
        previous_context: NetworkContext | None = None
        previous_name = LOCAL
        for edge in edges:
            context = self.contexts.get(edge.target)
            if context is not None and previous_context is not None:
                conflict = previous_context.conflicts_with(context)
                if conflict:
                    raise RouteError(
                        f"route to '{target}' crosses an environment boundary: "
                        f"{previous_name} ({previous_context.environment}) -> "
                        f"{edge.target} ({context.environment}).\n"
                        f"Environments are kept separate on purpose. If this traversal is "
                        f"genuinely intended, set matching 'environment' values, or declare a "
                        f"dedicated node for '{edge.target}' in the {previous_context.environment} "
                        f"environment."
                    )
            if context is not None:
                previous_context, previous_name = context, edge.target

        return warnings

    # -- construction -----------------------------------------------------

    @classmethod
    def build(
        cls,
        edges: Iterable[RouteEdge],
        contexts: Mapping[str, NetworkContext] | None = None,
        direct_allowed: Iterable[str] = (),
    ) -> "RouteGraph":
        collected = tuple(edges)
        seen: set[tuple[str, str]] = set()
        for edge in collected:
            key = (edge.source, edge.target)
            if key in seen:
                raise ConfigError(
                    f"duplicate route declared: {edge.source} -> {edge.target}. "
                    f"Each hop pair must appear once."
                )
            seen.add(key)
        return cls(
            edges=collected,
            contexts=dict(contexts or {}),
            direct_allowed=frozenset(direct_allowed),
        )
