"""Inventory and operation-catalog loading and validation.

Two YAML files, both free of secrets so they can be committed and shared:

``inventory.yaml``
    ``hops``  -- every machine on the path (bastions, jump servers)
    ``hosts`` -- final targets, each declaring the ordered ``path`` of hops

``operations.yaml``
    ``operations`` -- the catalog of what may be run, bound to hosts by
    ``host_id`` (or by ``tags``), per PLAN.md's requirement that the operation
    config identifies which hosts it applies to.

Validation is strict and reports every problem it can find in one pass: a
misconfigured inventory should fail at load time, not halfway through a patch
run on a production server.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .context import (
    LoggingConfig,
    NetworkContext,
    bare_username,
    embedded_domain,
    qualify_username,
)
from .errors import ConfigError, RouteError
from .paths import config_dir
from .routegraph import LOCAL, Endpoint, RouteEdge, RouteGraph
from .template import placeholders

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

SSH_KINDS = frozenset({"ssh", "linux", "unix", "aix", "solaris"})
WINDOWS_KINDS = frozenset({"windows", "win"})
ALL_KINDS = SSH_KINDS | WINDOWS_KINDS

AUTH_METHODS = frozenset({"password", "key", "key+password", "agent"})
AUTOMATION_CHANNELS = frozenset({"ssh", "winrm", "wmi", "none"})
INTERACTIVE_CHANNELS = frozenset({"rdp", "ssh", "none"})
SHELLS = frozenset({"powershell", "cmd", "bash", "sh"})

DEFAULT_SSH_PORT = 22
DEFAULT_WINRM_PORT = 5985
DEFAULT_WINRM_SSL_PORT = 5986
DEFAULT_RDP_PORT = 3389
DEFAULT_STEP_TIMEOUT = 600


def _as_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where}: expected a mapping, got {type(value).__name__}")
    return dict(value)


def _as_str_tuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(v) for v in value)
    raise ConfigError(f"{where}: expected a string or list of strings")


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in mapping or mapping[key] in (None, ""):
        raise ConfigError(f"{where}: missing required field '{key}'")
    return mapping[key]


def _expand(path_value: str | None) -> Path | None:
    if not path_value:
        return None
    return Path(os.path.expandvars(str(path_value))).expanduser()


def is_windows_kind(kind: str) -> bool:
    return kind.lower() in WINDOWS_KINDS


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthConfig:
    """How to authenticate to one node.  Holds no secret -- only the method."""

    method: str = "password"
    key_file: Path | None = None
    #: WinRM transport: ntlm (default, works through a tunnel), kerberos,
    #: credssp (needed only for double-hop to network resources), or basic.
    transport: str = "ntlm"
    #: Which NTLM implementation computes the response, for transport: ntlm.
    #:   'auto'   (default) -- decide from the route: a DIRECT (no-bastion) host
    #:            uses the pure-Python provider, a host reached THROUGH a bastion
    #:            uses SSPI over the loopback tunnel. This is what a large,
    #:            mixed fleet wants: the right choice falls out of each server's
    #:            own `via:` with nothing to set by hand.
    #:   'python' -- force the pure-Python provider. Needed when this client's
    #:            Group Policy sets "Restrict NTLM: Outgoing NTLM = Deny" and the
    #:            target is not on the allow-list, where SSPI would refuse locally
    #:            (SEC_E_LOGON_DENIED) before the server ever sees the credential.
    #:   'sspi'   -- force Windows' native SSPI.
    #: Ignored for non-ntlm transports.
    ntlm_provider: str = "auto"
    #: Prompt for a username instead of taking it from the inventory.
    prompt_username: bool = False

    @property
    def uses_key(self) -> bool:
        return self.method in ("key", "key+password")

    @property
    def uses_password(self) -> bool:
        return self.method in ("password", "key+password")

    @classmethod
    def parse(cls, raw: Any, where: str) -> "AuthConfig":
        data = _as_mapping(raw, where)
        method = str(data.get("method", "password")).lower()
        if method not in AUTH_METHODS:
            raise ConfigError(
                f"{where}.method: '{method}' is not one of {sorted(AUTH_METHODS)}"
            )
        key_file = _expand(data.get("key_file"))
        if method in ("key", "key+password") and key_file is None:
            raise ConfigError(f"{where}: method '{method}' requires 'key_file'")
        transport = str(data.get("transport", "ntlm")).lower()
        ntlm_provider = str(data.get("ntlm_provider", "auto")).lower()
        if ntlm_provider not in ("auto", "sspi", "python"):
            raise ConfigError(
                f"{where}.ntlm_provider: '{ntlm_provider}' is not one of "
                f"['auto', 'sspi', 'python']"
            )
        return cls(
            method=method,
            key_file=key_file,
            transport=transport,
            ntlm_provider=ntlm_provider,
            prompt_username=bool(data.get("prompt_username", False)),
        )


ROLES = frozenset({"bastion", "jump", "target", "node"})


@dataclass(frozen=True)
class Node:
    """Fields shared by hops and hosts."""

    id: str
    kind: str
    host: str
    user: str | None
    auth: AuthConfig
    port: int
    winrm_port: int
    rdp_port: int
    automation: str
    interactive: str
    description: str
    tags: tuple[str, ...]
    vars: Mapping[str, Any]
    #: Active Directory / NT domain. Windows auth against a domain-joined host
    #: fails with a bare username, and the failure looks like a wrong password.
    domain: str = ""
    #: Where this node sits, for routing and compliance decisions.
    context: NetworkContext = field(default_factory=NetworkContext)
    role: str = "node"

    @property
    def is_windows(self) -> bool:
        return is_windows_kind(self.kind)

    @property
    def automation_port(self) -> int:
        if self.automation == "winrm":
            return self.winrm_port
        return self.port

    @property
    def qualified_user(self) -> str | None:
        """The username as it should be presented: ``DOMAIN\\user`` when a
        ``domain:`` is set, on every kind of node.

        Windows auth needs it. So do Unix hosts joined to AD through SSSD,
        winbind or Centrify, which accept ``DOMAIN\\user`` over SSH like any
        other login name -- so this is not qualified by node kind. A node that
        wants a bare name simply omits ``domain:``; a username that already
        carries one is left as it is.
        """
        return qualify_username(self.user, self.domain)


@dataclass(frozen=True)
class Hop(Node):
    """An intermediate machine on the path to a target."""


@dataclass(frozen=True)
class Host(Node):
    """A final target that operations run against."""

    path: tuple[str, ...] = ()

    @property
    def host_id(self) -> str:
        return self.id


#: Which node field a `via:` endpoint's port should populate, by protocol.
_PORT_FIELD_FOR = {
    "ssh": "port",
    "winrm": "winrm_port",
    "winrm-ssl": "winrm_port",
    "rdp": "rdp_port",
}


def _via_blocks(data: Mapping[str, Any], where: str) -> list[Any]:
    """The `via:` declarations on one node, always as a list.

    A node is usually reached one way, so `via:` is normally a single mapping.
    A list is accepted for the rarer case of a node reachable from more than one
    source -- resolution then picks the shortest declared path as it always has.
    """
    via = data.get("via")
    if via is None:
        return []
    if isinstance(via, Mapping):
        return [via]
    if isinstance(via, Sequence) and not isinstance(via, str):
        return list(via)
    raise ConfigError(f"{where}.via: expected a mapping, or a list of mappings")


def _via_edge(
    node_id: str,
    block: Any,
    where: str,
    *,
    domain: str = "",
    username: str | None = None,
    description: str = "",
) -> RouteEdge:
    """Turn one `via:` block into the same edge a `routes:` entry would produce.

    Identity travels with the node, never with the edge: ``domain``/``username``
    are copied from the node record rather than restated here, so the two cannot
    disagree.
    """
    if not isinstance(block, Mapping):
        raise ConfigError(f"{where}: expected a mapping with 'from' and an address")
    data = dict(block)
    source = str(data.pop("from", "") or data.pop("source", "") or "").strip()
    if not source:
        raise ConfigError(
            f"{where}.from: required -- name the node this one is reached from, "
            f"or '{LOCAL}' for the operator's own machine"
        )
    data["source"] = source
    data["target"] = node_id
    data["domain"] = domain
    if username:
        data["username"] = username
    if description and "description" not in data:
        data["description"] = description
    # Delegates to the same parser the `routes:` block uses, so the inline
    # hostname/port/protocol shorthand, the RDP-cannot-automate rule and every
    # error message are shared rather than reimplemented.
    return RouteEdge.parse(data, where)


def _via_edges(node: Node, raw: Mapping[str, Any], where: str) -> list[RouteEdge]:
    blocks = _via_blocks(raw, where)
    return [
        _via_edge(
            node.id,
            block,
            f"{where}.via" if len(blocks) == 1 else f"{where}.via[{i}]",
            domain=node.domain,
            username=node.user,
            description=node.description,
        )
        for i, block in enumerate(blocks)
    ]


def _parse_node(
    node_id: str, raw: Any, where: str, *, default_automation: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the fields common to hops and hosts.

    Returns ``(constructor_kwargs, raw_data)`` -- callers need the raw mapping to
    read the few fields that only hosts have.
    """
    data = _as_mapping(raw, where)
    kind = str(data.get("kind", "ssh")).lower()
    if kind not in ALL_KINDS:
        raise ConfigError(f"{where}.kind: '{kind}' is not one of {sorted(ALL_KINDS)}")

    windows = is_windows_kind(kind)
    automation = str(
        data.get("automation", default_automation or ("winrm" if windows else "ssh"))
    ).lower()
    if automation not in AUTOMATION_CHANNELS:
        raise ConfigError(
            f"{where}.automation: '{automation}' is not one of {sorted(AUTOMATION_CHANNELS)}"
        )
    if not windows and automation not in ("ssh", "none"):
        raise ConfigError(
            f"{where}.automation: '{automation}' is only valid for windows nodes; "
            f"kind '{kind}' must use 'ssh'"
        )

    interactive = str(data.get("interactive", "rdp" if windows else "ssh")).lower()
    if interactive not in INTERACTIVE_CHANNELS:
        raise ConfigError(
            f"{where}.interactive: '{interactive}' is not one of {sorted(INTERACTIVE_CHANNELS)}"
        )
    if interactive == "rdp" and not windows:
        raise ConfigError(f"{where}.interactive: 'rdp' requires a windows kind")

    role = str(data.get("role", "node")).lower()
    if role not in ROLES:
        raise ConfigError(f"{where}.role: '{role}' is not one of {sorted(ROLES)}")

    # `hostname`/`username` are the spellings used in the connectivity spec;
    # `host`/`user` are accepted as equivalents.
    hostname = data.get("hostname") or data.get("host")
    username = data.get("username") or data.get("user")

    # A username may carry its own domain (`CORP\me`, `me@corp.net`). When it
    # does, `qualify_username` leaves it alone -- so a `domain:` saying something
    # different is silently discarded, and you authenticate as an identity the
    # file never states. Refuse it rather than pick a winner.
    node_domain = str(data.get("domain", ""))
    carried = embedded_domain(str(username) if username else None)

    if carried and node_domain and carried.casefold() != node_domain.casefold():
        raise ConfigError(
            f"{where}: username '{username}' already carries the domain '{carried}', "
            f"but domain: '{node_domain}' says otherwise. The login would use "
            f"'{carried}' and '{node_domain}' would be silently ignored.\n"
            f"Either drop 'domain:' and keep the qualified username, or set "
            f"username: '{bare_username(str(username))}' and let "
            f"domain: '{node_domain}' qualify it."
        )

    ports = {"port": DEFAULT_SSH_PORT, "winrm_port": DEFAULT_WINRM_PORT, "rdp_port": DEFAULT_RDP_PORT}

    # A node that declares `via:` has already said where it lives, as seen from
    # the node it is reached from. Repeating that as a bare `hostname:` is what
    # let the two drift apart, so it is optional here and taken from `via:`.
    via_blocks = _via_blocks(data, where)
    if via_blocks:
        first = _via_edge(node_id, via_blocks[0], f"{where}.via")
        if not hostname:
            hostname = first.primary.hostname
        for endpoint in (first.automation, first.interactive):
            if endpoint is None:
                continue
            key = _PORT_FIELD_FOR.get(endpoint.protocol)
            if key and key not in data:
                ports[key] = endpoint.port

    if not hostname:
        raise ConfigError(
            f"{where}: missing required field 'hostname'. Give it one, or declare a "
            f"'via:' block saying where this node is reached from and at what address."
        )

    return {
        "id": node_id,
        "kind": kind,
        "host": str(hostname),
        "user": str(username) if username else None,
        "auth": AuthConfig.parse(data.get("auth"), f"{where}.auth"),
        "port": int(data.get("port", ports["port"])),
        "winrm_port": int(data.get("winrm_port", ports["winrm_port"])),
        "rdp_port": int(data.get("rdp_port", ports["rdp_port"])),
        "automation": automation,
        "interactive": interactive,
        "description": str(data.get("description", "")),
        "tags": _as_str_tuple(data.get("tags"), f"{where}.tags"),
        "vars": dict(_as_mapping(data.get("vars"), f"{where}.vars")),
        "domain": str(data.get("domain", "")),
        "context": NetworkContext.parse(_as_mapping(data.get("context"), f"{where}.context")),
        "role": role,
    }, data


@dataclass(frozen=True)
class Inventory:
    hops: Mapping[str, Hop]
    hosts: Mapping[str, Host]
    source: Path | None = None
    #: Explicit connectivity. Built from declared ``routes:`` edges, or compiled
    #: from each host's ``path:`` shorthand -- both end up as the same graph.
    graph: RouteGraph = field(default_factory=RouteGraph)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    agent_prefix: str = "AGT"
    session_prefix: str = "SES"
    #: True when connectivity came from an explicit ``routes:`` block.
    routes_declared: bool = False

    def node_context(self, node_id: str) -> NetworkContext:
        node = self.hosts.get(node_id) or self.hops.get(node_id)
        return node.context if node else NetworkContext()

    def hop(self, hop_id: str) -> Hop:
        try:
            return self.hops[hop_id]
        except KeyError:
            known = ", ".join(sorted(self.hops)) or "(none)"
            raise ConfigError(f"unknown hop '{hop_id}'. Configured hops: {known}") from None

    def get(self, host_id: str) -> Host:
        try:
            return self.hosts[host_id]
        except KeyError:
            known = ", ".join(sorted(self.hosts)) or "(none)"
            raise ConfigError(
                f"unknown host '{host_id}'. Configured hosts: {known}"
            ) from None

    def node(self, node_id: str) -> Node:
        """Look up a hop *or* a host by id -- used by ``ac rdp``/``ac shell``."""
        if node_id in self.hosts:
            return self.hosts[node_id]
        if node_id in self.hops:
            return self.hops[node_id]
        known = ", ".join(sorted(set(self.hosts) | set(self.hops))) or "(none)"
        raise ConfigError(f"unknown host or hop '{node_id}'. Configured: {known}")


def load_inventory(path: str | Path | None = None) -> Inventory:
    """Load and validate ``inventory.yaml``."""
    resolved = _resolve_config_path(path, "inventory.yaml")
    raw = _read_yaml(resolved)

    #: Edges compiled from each node's own `via:` block, in declaration order.
    via_edges: list[RouteEdge] = []

    hops: dict[str, Hop] = {}
    for hop_id, hop_raw in _as_mapping(raw.get("hops"), "hops").items():
        where = f"hops.{hop_id}"
        fields, data = _parse_node(str(hop_id), hop_raw, where)
        hop = Hop(**fields)
        hops[str(hop_id)] = hop
        via_edges.extend(_via_edges(hop, data, where))

    hosts: dict[str, Host] = {}
    for host_id, host_raw in _as_mapping(raw.get("hosts"), "hosts").items():
        where = f"hosts.{host_id}"
        fields, data = _parse_node(str(host_id), host_raw, where)
        declared_id = data.get("host_id")
        if declared_id and str(declared_id) != str(host_id):
            raise ConfigError(
                f"{where}.host_id: '{declared_id}' does not match its key '{host_id}'"
            )
        hop_path = _as_str_tuple(data.get("path"), f"{where}.path")
        if "package_share" in data:
            raise ConfigError(
                f"{where}.package_share: paths belong to the job, not the machine. "
                f"Declare it as a parameter of the operation that uses it and supply "
                f"the value in the brief."
            )
        host = Host(**fields, path=hop_path)
        hosts[str(host_id)] = host
        via_edges.extend(_via_edges(host, data, where))

    if not hosts:
        raise ConfigError(f"{resolved}: no hosts defined")

    logging_config = LoggingConfig.parse(_as_mapping(raw.get("logging"), "logging"))
    agent_raw = _as_mapping(raw.get("agent"), "agent")

    contexts = {node.id: node.context for node in (*hops.values(), *hosts.values())}
    # Three ways to declare the same graph, most explicit first. `via:` on each
    # node is the one to write: it keeps a machine's address next to its
    # identity, so there is a single place to edit and nothing to keep in sync.
    # A standalone `routes:` block still wins where one is present, and `path:`
    # remains for the simple linear case.
    routes_raw = raw.get("routes")
    if routes_raw:
        if not isinstance(routes_raw, Sequence) or isinstance(routes_raw, str):
            raise ConfigError(f"{resolved}: 'routes' must be a list of edges")
        edges = [RouteEdge.parse(item, f"routes[{i}]") for i, item in enumerate(routes_raw)]
        if via_edges:
            raise ConfigError(
                f"{resolved}: connectivity is declared twice -- a top-level 'routes:' block "
                f"and a 'via:' on "
                f"{', '.join(sorted({e.target for e in via_edges})[:3])}. Pick one. "
                f"'via:' is preferred: it keeps each machine's address beside its identity."
            )
        routes_declared = True
    elif via_edges:
        edges = via_edges
        routes_declared = True
    else:
        edges = _compile_path_shorthand(hops, hosts)
        routes_declared = False

    graph = RouteGraph.build(edges, contexts)

    inventory = Inventory(
        hops=hops,
        hosts=hosts,
        source=resolved,
        graph=graph,
        logging=logging_config,
        agent_prefix=str(agent_raw.get("id_prefix", agent_raw.get("prefix", "AGT"))),
        session_prefix=str(agent_raw.get("session_prefix", "SES")),
        routes_declared=routes_declared,
    )
    _validate_inventory(inventory)
    return inventory


def _endpoint_for(node: Node, *, automation: bool) -> Endpoint | None:
    """Turn a node's own settings into an endpoint, for the ``path:`` shorthand."""
    if automation:
        if node.automation == "none":
            return None
        protocol = "winrm" if node.automation == "winrm" else node.automation
        port = node.winrm_port if node.automation == "winrm" else node.port
        return Endpoint(hostname=node.host, port=port, protocol=protocol)
    if node.interactive == "none":
        return None
    if node.interactive == "rdp":
        return Endpoint(hostname=node.host, port=node.rdp_port, protocol="rdp")
    return Endpoint(hostname=node.host, port=node.port, protocol="ssh")


def _compile_path_shorthand(
    hops: Mapping[str, Hop], hosts: Mapping[str, Host]
) -> list[RouteEdge]:
    """Compile each host's ``path:`` into explicit edges.

    ``path: [bastion1, jump1]`` on a host is already an explicit statement of
    intent; it is just a more compact one. Compiling it into the same graph the
    ``routes:`` block produces means there is a single resolution engine, and a
    single place where connectivity is validated.

    Edges are de-duplicated: many hosts share a bastion, and each would
    otherwise re-declare ``local -> bastion1``.
    """
    edges: dict[tuple[str, str], RouteEdge] = {}

    def add(source: str, node: Node) -> None:
        key = (source, node.id)
        if key in edges:
            return
        edges[key] = RouteEdge(
            source=source,
            target=node.id,
            automation=_endpoint_for(node, automation=True),
            interactive=_endpoint_for(node, automation=False),
            domain=node.domain,
            username=node.user,
            description=node.description,
        )

    for host in hosts.values():
        previous = LOCAL
        for hop_id in host.path:
            hop = hops.get(hop_id)
            if hop is None:
                # Reported properly by _validate_inventory; skip here so the
                # error names the host rather than failing inside the compiler.
                previous = hop_id
                continue
            add(previous, hop)
            previous = hop_id
        add(previous, host)

    return list(edges.values())


def _validate_inventory(inventory: Inventory) -> None:
    """Fail at load time, not halfway through a run on a production server."""
    problems: list[str] = []

    for host in inventory.hosts.values():
        if host.id in inventory.hops:
            problems.append(
                f"'{host.id}' is defined as both a hop and a host; ids must be unique"
            )

        if not inventory.routes_declared:
            seen: set[str] = set()
            for hop_id in host.path:
                if hop_id not in inventory.hops:
                    problems.append(
                        f"hosts.{host.id}.path references unknown hop '{hop_id}'"
                    )
                if hop_id in seen:
                    problems.append(
                        f"hosts.{host.id}.path visits hop '{hop_id}' more than once"
                    )
                seen.add(hop_id)
            if not host.path and host.automation != "none":
                # A direct connection bypasses every bastion, which is exactly
                # what the hierarchy exists to prevent. Allowed, but only when
                # said out loud.
                if not host.vars.get("allow_direct"):
                    problems.append(
                        f"hosts.{host.id}: empty 'path' means connecting directly, bypassing "
                        f"every bastion. Set vars.allow_direct: true if that is intended."
                    )

    # Every declared route must name declared nodes.
    known = set(inventory.hops) | set(inventory.hosts) | {LOCAL}
    for edge in inventory.graph.edges:
        for role, name in (("source", edge.source), ("target", edge.target)):
            if name not in known:
                problems.append(
                    f"connectivity: {edge.source} -> {edge.target} has a {role} '{name}' that "
                    f"is not defined under 'hops:' or 'hosts:'"
                )

    if problems:
        raise ConfigError("inventory is invalid:\n  - " + "\n  - ".join(problems))

    # Resolve every host now, so a missing or ambiguous route surfaces at load
    # time rather than at connect time. Interactive-only hosts are exempt --
    # they are reached by a human, not by the automation channel.
    route_problems: list[str] = []
    for host in inventory.hosts.values():
        if host.automation == "none":
            continue
        try:
            inventory.graph.resolve(host.id, require_automation=True)
        except (RouteError, ConfigError) as exc:
            first = str(exc).strip().splitlines()[0]
            route_problems.append(f"hosts.{host.id}: {first}")
    if route_problems:
        raise ConfigError(
            "inventory has unroutable hosts:\n  - " + "\n  - ".join(route_problems)
        )


# --------------------------------------------------------------------------
# Operation catalog
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Param:
    name: str
    required: bool = True
    default: Any = None
    description: str = ""

    @classmethod
    def parse(cls, raw: Any, where: str) -> "Param":
        if isinstance(raw, str):
            return cls(name=raw)
        data = _as_mapping(raw, where)
        name = str(_require(data, "name", where))
        return cls(
            name=name,
            required=bool(data.get("required", "default" not in data)),
            default=data.get("default"),
            description=str(data.get("description", "")),
        )


@dataclass(frozen=True)
class Expect:
    """What "this step worked" means.  Empty means 'exit code 0'."""

    exit_code: int | None = 0
    any_exit_code: bool = False
    stdout_contains: str | None = None
    stdout_not_contains: str | None = None
    stdout_regex: str | None = None

    @classmethod
    def parse(cls, raw: Any, where: str) -> "Expect":
        if raw is None:
            return cls()
        data = _as_mapping(raw, where)
        any_exit = bool(data.get("any_exit_code", False))
        exit_code = data.get("exit_code", None if any_exit else 0)
        allowed = {
            "exit_code",
            "any_exit_code",
            "stdout_contains",
            "stdout_not_contains",
            "stdout_regex",
        }
        unknown = set(data) - allowed
        if unknown:
            raise ConfigError(
                f"{where}: unknown expectation key(s) {sorted(unknown)}; "
                f"valid keys are {sorted(allowed)}"
            )
        return cls(
            exit_code=None if exit_code is None else int(exit_code),
            any_exit_code=any_exit,
            stdout_contains=_opt_str(data.get("stdout_contains")),
            stdout_not_contains=_opt_str(data.get("stdout_not_contains")),
            stdout_regex=_opt_str(data.get("stdout_regex")),
        )


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


@dataclass(frozen=True)
class CollectSpec:
    """One source of diagnostic material to gather when a step fails."""

    files: tuple[str, ...] = ()
    eventlog: Mapping[str, Any] | None = None
    command: str | None = None
    tail_lines: int = 200

    @classmethod
    def parse(cls, raw: Any, where: str) -> "CollectSpec":
        data = _as_mapping(raw, where)
        eventlog = data.get("eventlog")
        return cls(
            files=_as_str_tuple(data.get("files"), f"{where}.files"),
            eventlog=_as_mapping(eventlog, f"{where}.eventlog") if eventlog else None,
            command=_opt_str(data.get("command")),
            tail_lines=int(data.get("tail_lines", 200)),
        )


@dataclass(frozen=True)
class OnFailure:
    """Diagnostics to gather and hints to surface when a step fails.

    The collected material and the matching hint are handed straight back to the
    agent, which is what makes "read the logs and resolve the issue" tractable.
    """

    collect: tuple[CollectSpec, ...] = ()
    hints: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: Any, where: str) -> "OnFailure | None":
        if raw is None:
            return None
        data = _as_mapping(raw, where)
        collect_raw = data.get("collect") or []
        if isinstance(collect_raw, Mapping):
            collect_raw = [collect_raw]
        collect = tuple(
            CollectSpec.parse(item, f"{where}.collect[{i}]")
            for i, item in enumerate(collect_raw)
        )
        hints = {
            str(k): str(v)
            for k, v in _as_mapping(data.get("hints"), f"{where}.hints").items()
        }
        return cls(collect=collect, hints=hints)

    def hint_for(self, exit_code: int | None) -> str | None:
        """The hint matching ``exit_code``, falling back to a ``'*'`` catch-all."""
        if exit_code is not None and str(exit_code) in self.hints:
            return self.hints[str(exit_code)]
        return self.hints.get("*")


@dataclass(frozen=True)
class Step:
    id: str
    run: str
    desc: str = ""
    shell: str = "powershell"
    expect: Expect = field(default_factory=Expect)
    on_failure: OnFailure | None = None
    timeout_s: int = DEFAULT_STEP_TIMEOUT
    destructive: bool = False
    requires_permission: bool = False
    continue_on_failure: bool = False

    @classmethod
    def parse(cls, raw: Any, where: str, *, default_shell: str) -> "Step":
        data = _as_mapping(raw, where)
        step_id = str(_require(data, "id", where))
        shell = str(data.get("shell", default_shell)).lower()
        if shell not in SHELLS:
            raise ConfigError(f"{where}.shell: '{shell}' is not one of {sorted(SHELLS)}")
        return cls(
            id=step_id,
            run=str(_require(data, "run", where)),
            desc=str(data.get("desc", data.get("description", ""))),
            shell=shell,
            expect=Expect.parse(data.get("expect"), f"{where}.expect"),
            on_failure=OnFailure.parse(data.get("on_failure"), f"{where}.on_failure"),
            timeout_s=int(data.get("timeout_s", DEFAULT_STEP_TIMEOUT)),
            destructive=bool(data.get("destructive", False)),
            requires_permission=bool(data.get("requires_permission", False)),
            continue_on_failure=bool(data.get("continue_on_failure", False)),
        )


@dataclass(frozen=True)
class Operation:
    id: str
    description: str = ""
    host_ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    params: tuple[Param, ...] = ()
    steps: tuple[Step, ...] = ()
    requires_permission: bool = True
    destructive: bool = False

    @property
    def is_gated(self) -> bool:
        """True if this operation may not run without explicit confirmation."""
        return (
            self.requires_permission
            or self.destructive
            or any(s.requires_permission or s.destructive for s in self.steps)
        )

    def param(self, name: str) -> Param | None:
        for p in self.params:
            if p.name == name:
                return p
        return None

    def applies_to(self, host: Host) -> bool:
        if "*" in self.host_ids:
            return True
        if host.id in self.host_ids:
            return True
        return bool(set(self.tags) & set(host.tags))

    @classmethod
    def parse(cls, raw: Any, where: str) -> "Operation":
        data = _as_mapping(raw, where)
        op_id = str(_require(data, "id", where))
        params_raw = data.get("params") or []
        if isinstance(params_raw, (str, Mapping)):
            params_raw = [params_raw]
        params = tuple(
            Param.parse(p, f"{where}.params[{i}]") for i, p in enumerate(params_raw)
        )
        default_shell = str(data.get("shell", "powershell")).lower()
        steps_raw = data.get("steps") or []
        if not isinstance(steps_raw, Sequence) or isinstance(steps_raw, str):
            raise ConfigError(f"{where}.steps: expected a list of steps")
        steps = tuple(
            Step.parse(s, f"{where}.steps[{i}]", default_shell=default_shell)
            for i, s in enumerate(steps_raw)
        )
        if not steps:
            raise ConfigError(f"{where}: operation '{op_id}' has no steps")

        seen_steps: set[str] = set()
        for step in steps:
            if step.id in seen_steps:
                raise ConfigError(f"{where}: duplicate step id '{step.id}'")
            seen_steps.add(step.id)

        host_ids = _as_str_tuple(data.get("host_ids"), f"{where}.host_ids")
        tags = _as_str_tuple(data.get("tags"), f"{where}.tags")
        if not host_ids and not tags:
            raise ConfigError(
                f"{where}: operation '{op_id}' must declare 'host_ids' (or 'tags') so it is "
                f"clear which hosts it may run on. Use host_ids: ['*'] to allow every host."
            )

        destructive = bool(data.get("destructive", False)) or any(
            s.destructive for s in steps
        )
        return cls(
            id=op_id,
            description=str(data.get("description", "")),
            host_ids=host_ids,
            tags=tags,
            params=params,
            steps=steps,
            # Gated by default: an operation must opt *out* of asking permission.
            requires_permission=bool(data.get("requires_permission", True)),
            destructive=destructive,
        )


@dataclass(frozen=True)
class Catalog:
    operations: Mapping[str, Operation]
    source: Path | None = None

    def get(self, op_id: str) -> Operation:
        try:
            return self.operations[op_id]
        except KeyError:
            known = ", ".join(sorted(self.operations)) or "(none)"
            raise ConfigError(
                f"unknown operation '{op_id}'. Configured operations: {known}"
            ) from None

    def for_host(self, host: Host) -> list[Operation]:
        """Operations permitted on ``host``, per their host_id/tag binding."""
        return [op for op in self.operations.values() if op.applies_to(host)]


def load_operations(path: str | Path | None = None) -> Catalog:
    """Load and validate ``operations.yaml``."""
    resolved = _resolve_config_path(path, "operations.yaml")
    raw = _read_yaml(resolved)

    ops_raw = raw.get("operations") or []
    if not isinstance(ops_raw, Sequence) or isinstance(ops_raw, str):
        raise ConfigError(f"{resolved}: 'operations' must be a list")

    operations: dict[str, Operation] = {}
    for i, op_raw in enumerate(ops_raw):
        op = Operation.parse(op_raw, f"operations[{i}]")
        if op.id in operations:
            raise ConfigError(f"{resolved}: duplicate operation id '{op.id}'")
        operations[op.id] = op

    return Catalog(operations=operations, source=resolved)


def validate_catalog_against_inventory(catalog: Catalog, inventory: Inventory) -> list[str]:
    """Cross-file checks.  Returns warnings; hard errors raise.

    A wrong ``host_id`` in the operation catalog is the mistake most likely to
    run a patch job on the wrong machine, so it is an error, not a warning.
    """
    warnings: list[str] = []
    known_tags = {tag for host in inventory.hosts.values() for tag in host.tags}
    for op in catalog.operations.values():
        for host_id in op.host_ids:
            if host_id != "*" and host_id not in inventory.hosts:
                raise ConfigError(
                    f"operation '{op.id}' targets unknown host_id '{host_id}'. "
                    f"Known hosts: {', '.join(sorted(inventory.hosts)) or '(none)'}"
                )
        for tag in op.tags:
            if tag not in known_tags:
                warnings.append(
                    f"operation '{op.id}' targets tag '{tag}', which no host declares"
                )
        if not any(op.applies_to(h) for h in inventory.hosts.values()):
            warnings.append(f"operation '{op.id}' matches no configured host")
    return warnings


def operation_variables(op: Operation, host: Host, params: Mapping[str, Any]) -> dict[str, Any]:
    """Build the variable map a step template is rendered against.

    Identity fields come first so an operation can reference ``{{host}}`` or
    ``{{user}}``; explicit params win over everything.

    Only facts about the *machine* live here. A path the job works on is a
    parameter, declared by the operation and supplied by the brief -- that way a
    missing one is refused up front by name, rather than rendering as an empty
    string and failing on the server halfway through.
    """
    variables: dict[str, Any] = {
        "host_id": host.id,
        "host": host.host,
        "user": host.user or "",
        "kind": host.kind,
    }
    variables.update(host.vars)
    for p in op.params:
        if p.default is not None:
            variables[p.name] = p.default
    variables.update({k: v for k, v in params.items() if v is not None})

    missing = [
        p.name
        for p in op.params
        if p.required and (p.name not in variables or variables[p.name] in (None, ""))
    ]
    if missing:
        raise ConfigError(
            f"operation '{op.id}' requires parameter(s): {', '.join(missing)}"
        )
    return variables


def unresolved_variables(op: Operation, variables: Mapping[str, Any]) -> list[str]:
    """Placeholders used by any step that ``variables`` cannot satisfy."""
    missing: list[str] = []
    for step in op.steps:
        for name in placeholders(step.run):
            if name not in variables and name not in missing:
                missing.append(name)
    return missing


# --------------------------------------------------------------------------
# Loading helpers
# --------------------------------------------------------------------------


def _resolve_config_path(path: str | Path | None, default_name: str) -> Path:
    if path is not None:
        resolved = Path(path).expanduser()
        if not resolved.exists():
            raise ConfigError(f"config file not found: {resolved}")
        return resolved

    directory = config_dir()
    candidate = directory / default_name
    if candidate.exists():
        return candidate

    # Fall back to the shipped example so a fresh clone is not dead on arrival.
    example = directory / default_name.replace(".yaml", ".example.yaml")
    if example.exists():
        return example

    raise ConfigError(
        f"config file not found: {candidate}\n"
        f"Copy {example.name} to {candidate.name} and edit it for your environment."
    )


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise ConfigError(f"{path}: top level must be a mapping")
    return dict(data)


def load_all(
    inventory_path: str | Path | None = None,
    operations_path: str | Path | None = None,
) -> tuple[Inventory, Catalog, list[str]]:
    """Load both files and cross-validate.  Returns ``(inventory, catalog, warnings)``."""
    inventory = load_inventory(inventory_path)
    catalog = load_operations(operations_path)
    warnings = validate_catalog_against_inventory(catalog, inventory)
    return inventory, catalog, warnings
