"""Turn a resolved connectivity path into an executable plan.

:mod:`routegraph` answers *"is there a declared path, and what is it?"*.  This
module answers *"how do we actually traverse it?"* -- which legs are SSH, where
the tunnel is anchored, and how the final hop runs commands.

Three shapes are supported:

``ssh``
    SSH legs all the way.  Paramiko chains ``direct-tcpip`` channels hop to hop,
    the same mechanism as OpenSSH's ``ProxyJump``.

``winrm``
    SSH legs, then a Windows target.  A local port forward is anchored at the
    last SSH hop and PowerShell Remoting runs over it.

``nested-winrm``
    SSH legs, then a Windows jump server, then a Windows target.  PSRP reaches
    the jump server over the tunnel; the final leg is an ``Invoke-Command`` run
    from it.  This is the bastion -> jump server -> target shape.

Every leg carries the :class:`~.routegraph.Endpoint` declared for it, so an
address that differs by vantage point -- ``localhost:44001`` on the operator's
machine, ``10.20.4.11:3389`` from the bastion -- is honoured rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Host, Inventory, Node
from .errors import RouteError
from .routegraph import (
    CHANNEL_NESTED_WINRM,
    CHANNEL_SSH,
    CHANNEL_WINRM,
    LOCAL,
    SSH_PROTOCOLS,
    WINRM_PROTOCOLS,
    Endpoint,
    ResolvedRoute,
    classify_chain,
)


@dataclass(frozen=True)
class Leg:
    """One machine on the route, and how it is addressed from the one before."""

    node: Node
    endpoint: Endpoint
    source: str
    interactive: Endpoint | None = None

    @property
    def id(self) -> str:
        return self.node.id

    @property
    def is_ssh(self) -> bool:
        return self.endpoint.protocol in SSH_PROTOCOLS

    @property
    def is_winrm(self) -> bool:
        return self.endpoint.protocol in WINRM_PROTOCOLS


@dataclass(frozen=True)
class Route:
    """How to reach one host, leg by leg."""

    host: Host
    legs: tuple[Leg, ...]
    channel: str
    resolved: ResolvedRoute

    # -- structure --------------------------------------------------------

    @property
    def ssh_legs(self) -> tuple[Leg, ...]:
        return tuple(leg for leg in self.legs if leg.is_ssh)

    @property
    def winrm_legs(self) -> tuple[Leg, ...]:
        return tuple(leg for leg in self.legs if leg.is_winrm)

    @property
    def ssh_hops(self) -> tuple[Node, ...]:
        """SSH machines, excluding the target when it is itself SSH."""
        legs = self.ssh_legs
        if self.channel == CHANNEL_SSH and legs and legs[-1].id == self.host.id:
            legs = legs[:-1]
        return tuple(leg.node for leg in legs)

    @property
    def windows_hops(self) -> tuple[Node, ...]:
        """Windows jump servers between the SSH chain and the target."""
        return tuple(leg.node for leg in self.winrm_legs if leg.id != self.host.id)

    @property
    def tunnel_origin_leg(self) -> Leg | None:
        """The last SSH *hop* -- where a local port forward is anchored.

        The target is excluded even when it is itself SSH: a tunnel is anchored
        at a machine you pass through, not at the destination.
        """
        legs = self.ssh_legs
        if legs and legs[-1].id == self.host.id:
            legs = legs[:-1]
        return legs[-1] if legs else None

    @property
    def tunnel_origin(self) -> Node | None:
        leg = self.tunnel_origin_leg
        return leg.node if leg else None

    @property
    def nodes(self) -> tuple[Node, ...]:
        """Every machine on the route, in order, ending with the target."""
        return tuple(leg.node for leg in self.legs)

    @property
    def final_leg(self) -> Leg:
        return self.legs[-1]

    @property
    def psrp_entry(self) -> Node:
        """The first Windows machine PSRP speaks to over the tunnel."""
        winrm = self.winrm_legs
        return winrm[0].node if winrm else self.host

    @property
    def nested_chain(self) -> tuple[Node, ...]:
        """Machines reached by nested ``Invoke-Command``, in order."""
        if self.channel != CHANNEL_NESTED_WINRM:
            return ()
        return tuple(leg.node for leg in self.winrm_legs[1:])

    @property
    def is_direct(self) -> bool:
        return len(self.legs) == 1

    def leg_for(self, node_id: str) -> Leg | None:
        return next((leg for leg in self.legs if leg.id == node_id), None)

    # -- reporting --------------------------------------------------------

    def describe(self) -> str:
        """``local -> bastion1 (ssh) -> jump1 (winrm) -> target1 (nested winrm)``.

        The final leg is labelled with the *execution shape* rather than the raw
        protocol, because "nested winrm" is the thing an operator needs to know
        about that hop -- it is the one whose commands are run by the machine
        before it.
        """
        final_label = {
            CHANNEL_SSH: "ssh",
            CHANNEL_WINRM: "winrm",
            CHANNEL_NESTED_WINRM: "nested winrm",
        }.get(self.channel, self.channel)

        parts = [LOCAL]
        for index, leg in enumerate(self.legs):
            label = final_label if index == len(self.legs) - 1 else leg.endpoint.protocol
            parts.append(f"{leg.id} ({label})")
        return " -> ".join(parts)

    def describe_verbose(self) -> str:
        lines = [f"{LOCAL}"]
        for leg in self.legs:
            marker = " [pre-established tunnel]" if leg.endpoint.preestablished else ""
            lines.append(
                f"  -> {leg.id:<20} {leg.endpoint.hostname}:{leg.endpoint.port}"
                f"/{leg.endpoint.protocol}{marker}"
            )
            context = leg.node.context.describe()
            if context != "(no context)":
                lines.append(f"     {context}")
        return "\n".join(lines)

    def hop_labels(self) -> list[dict[str, str]]:
        """Per-node summary used by ``ac probe``, status output and the audit trail."""
        rows: list[dict[str, str]] = []
        for index, leg in enumerate(self.legs):
            if leg.id == self.host.id:
                role = "target"
            elif index == 0:
                role = "bastion"
            else:
                role = "jump"
            rows.append(
                {
                    "id": leg.id,
                    "role": leg.node.role if leg.node.role != "node" else role,
                    "source": leg.source,
                    "address": f"{leg.endpoint.hostname}:{leg.endpoint.port}",
                    "channel": leg.endpoint.protocol,
                    "preestablished": str(leg.endpoint.preestablished),
                    "context": leg.node.context.describe(),
                    "domain": leg.node.domain,
                }
            )
        return rows


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def _node_for(inventory: Inventory, node_id: str) -> Node:
    node = inventory.hosts.get(node_id) or inventory.hops.get(node_id)
    if node is None:
        raise RouteError(
            f"route references '{node_id}', which is not defined under 'hops:' or "
            f"'hosts:' in inventory.yaml. Every node on a route must be declared."
        )
    return node


def _build_legs(inventory: Inventory, resolved: ResolvedRoute) -> tuple[Leg, ...]:
    return tuple(
        Leg(
            node=_node_for(inventory, edge.target),
            endpoint=edge.primary,
            source=edge.source,
            interactive=edge.interactive,
        )
        for edge in resolved.edges
    )


def plan_route(inventory: Inventory, host_id: str) -> Route:
    """Resolve and validate the declared route to ``host_id``.

    Raises before any socket is opened if the path is not declared, is
    ambiguous, crosses an environment boundary, or cannot be traversed.
    """
    host = inventory.get(host_id)
    resolved = inventory.graph.resolve(host_id, require_automation=True)
    legs = _build_legs(inventory, resolved)
    if not legs:  # pragma: no cover - resolve() guarantees at least one edge
        raise RouteError(f"route to '{host_id}' resolved to no legs")
    channel = classify_chain(host_id, resolved.edges)
    return Route(host=host, legs=legs, channel=channel, resolved=resolved)


def plan_hop_route(inventory: Inventory, node_id: str) -> Route:
    """Route to a *hop* rather than a host.

    Used by ``ac rdp <jump>`` and ``ac shell <bastion>``: the machine becomes a
    temporary target, reached over the same declared path. Automation is not
    required, because the point is to hand a human an interactive session.
    """
    if node_id in inventory.hosts:
        return plan_route(inventory, node_id)

    hop = inventory.hop(node_id)
    resolved = inventory.graph.resolve(node_id, require_automation=False)
    legs = _build_legs(inventory, resolved)

    synthetic = Host(
        id=hop.id,
        kind=hop.kind,
        host=hop.host,
        user=hop.user,
        auth=hop.auth,
        port=hop.port,
        winrm_port=hop.winrm_port,
        rdp_port=hop.rdp_port,
        automation=hop.automation,
        interactive=hop.interactive,
        description=hop.description,
        tags=hop.tags,
        vars={**hop.vars, "allow_direct": True},
        domain=hop.domain,
        context=hop.context,
        role=hop.role,
        path=tuple(resolved.hops),
    )

    # Intermediate legs still have to be traversable; only the final one is
    # allowed to be interactive-only, since a human is taking it.
    channel = (
        classify_chain(node_id, resolved.edges)
        if legs[-1].is_ssh or legs[-1].is_winrm
        else CHANNEL_SSH
    )
    return Route(host=synthetic, legs=legs, channel=channel, resolved=resolved)
