"""Turning a declared hop path into an executable route."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from access_control.config import Inventory, load_inventory
from access_control.errors import ConfigError, RouteError
from access_control.route import (
    CHANNEL_NESTED_WINRM,
    CHANNEL_SSH,
    CHANNEL_WINRM,
    plan_hop_route,
    plan_route,
)


def inv(tmp_path: Path, body: str) -> Inventory:
    path = tmp_path / "inv.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return load_inventory(path)


class TestShapes:
    def test_ssh_target_through_one_bastion(self, inventory: Inventory) -> None:
        route = plan_route(inventory, "lin01")
        assert route.channel == CHANNEL_SSH
        assert [h.id for h in route.ssh_hops] == ["bastion1"]
        assert route.windows_hops == ()
        assert route.tunnel_origin is not None and route.tunnel_origin.id == "bastion1"

    def test_windows_target_direct_from_bastion(self, inventory: Inventory) -> None:
        route = plan_route(inventory, "win02")
        assert route.channel == CHANNEL_WINRM
        assert route.psrp_entry.id == "win02"
        assert route.nested_chain == ()

    def test_windows_target_behind_a_jump_server(self, inventory: Inventory) -> None:
        """PLAN.md's chain: local -> bastion -> jump server -> target."""
        route = plan_route(inventory, "win01")
        assert route.channel == CHANNEL_NESTED_WINRM
        assert [h.id for h in route.ssh_hops] == ["bastion1"]
        assert [h.id for h in route.windows_hops] == ["jump1"]
        assert route.psrp_entry.id == "jump1"
        assert [n.id for n in route.nested_chain] == ["win01"]

    def test_describe_reads_left_to_right(self, inventory: Inventory) -> None:
        assert plan_route(inventory, "win01").describe() == (
            "local -> bastion1 (ssh) -> jump1 (winrm) -> win01 (nested winrm)"
        )

    def test_nodes_end_with_the_target(self, inventory: Inventory) -> None:
        assert [n.id for n in plan_route(inventory, "win01").nodes] == [
            "bastion1",
            "jump1",
            "win01",
        ]

    def test_every_leg_carries_its_declared_endpoint(self, inventory: Inventory) -> None:
        """Addresses come from the route, not from a node's defaults."""
        legs = plan_route(inventory, "win01").legs
        assert [(leg.id, leg.endpoint.hostname, leg.endpoint.port) for leg in legs] == [
            ("bastion1", "bastion.example.net", 2222),
            ("jump1", "10.0.0.10", 5985),
            ("win01", "10.0.0.30", 5985),
        ]
        assert [leg.source for leg in legs] == ["local", "bastion1", "jump1"]

    def test_hop_labels_carry_roles_and_ports(self, inventory: Inventory) -> None:
        rows = plan_route(inventory, "win01").hop_labels()
        assert [r["role"] for r in rows] == ["bastion", "jump", "target"]
        assert rows[0]["address"] == "bastion.example.net:2222"
        assert rows[-1]["address"] == "10.0.0.30:5985"


class TestRejections:
    """Untraversable topologies are rejected when the config is *read*.

    Failing fast matters more than failing precisely: an operator finds out the
    route is impossible before they have typed three passwords, not halfway
    through a patch run.
    """

    def test_ssh_hop_after_a_windows_hop(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="comes after a Windows"):
            inv(
                tmp_path,
                """
                hops:
                  b: {kind: ssh, host: b.example}
                  w: {kind: windows, host: 10.0.0.1, user: u}
                  b2: {kind: ssh, host: b2.example}
                hosts:
                  t:
                    kind: windows
                    host: 10.0.0.2
                    user: u
                    path: [b, w, b2]
                """,
            )

    def test_two_windows_jump_servers_are_refused_clearly(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="Only one is supported"):
            inv(
                tmp_path,
                """
                hops:
                  b: {kind: ssh, host: b.example}
                  w1: {kind: windows, host: 10.0.0.1, user: u}
                  w2: {kind: windows, host: 10.0.0.2, user: u}
                hosts:
                  t:
                    kind: windows
                    host: 10.0.0.3
                    user: u
                    path: [b, w1, w2]
                """,
            )

    def test_linux_target_behind_a_windows_jump(self, tmp_path: Path) -> None:
        """An SSH target after a Windows hop is rejected before anything connects."""
        with pytest.raises(ConfigError, match="SSH leg to 't' comes after a Windows"):
            inv(
                tmp_path,
                """
                hops:
                  b: {kind: ssh, host: b.example}
                  w: {kind: windows, host: 10.0.0.1, user: u}
                hosts:
                  t:
                    kind: linux
                    host: 10.0.0.2
                    path: [b, w]
                """,
            )

    def test_automation_none_explains_the_alternative(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hops:
              b: {kind: ssh, host: b.example}
            hosts:
              t:
                kind: windows
                host: 10.0.0.2
                user: u
                automation: none
                path: [b]
            """,
        )
        with pytest.raises(RouteError, match="ac rdp t"):
            plan_route(inventory, "t")


class TestHopRoutes:
    def test_routing_to_a_hop_uses_the_path_before_it(self, inventory: Inventory) -> None:
        """`ac rdp jump1` must still go through the bastion in front of it."""
        route = plan_hop_route(inventory, "jump1")
        assert [h.id for h in route.ssh_hops] == ["bastion1"]
        assert route.host.id == "jump1"
        assert route.channel == CHANNEL_WINRM

    def test_routing_to_a_host_id_is_unchanged(self, inventory: Inventory) -> None:
        assert plan_hop_route(inventory, "win01").describe() == (
            plan_route(inventory, "win01").describe()
        )

    def test_routing_to_the_first_bastion_is_direct(self, inventory: Inventory) -> None:
        route = plan_hop_route(inventory, "bastion1")
        assert route.ssh_hops == ()
        assert route.host.id == "bastion1"
