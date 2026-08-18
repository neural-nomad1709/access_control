"""Explicit connectivity: declaration, resolution, and everything it refuses.

The rule under test throughout: **routes are declared, never discovered**, and a
missing declaration fails fast instead of falling back to a direct connection.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from access_control.config import load_inventory
from access_control.context import (
    AgentIdentity,
    LoggingConfig,
    NetworkContext,
    qualify_username,
)
from access_control.errors import ConfigError, RouteError
from access_control.route import plan_route
from access_control.routegraph import (
    CHANNEL_NESTED_WINRM,
    CHANNEL_SSH,
    CHANNEL_WINRM,
    LOCAL,
    Endpoint,
    RouteEdge,
    RouteGraph,
)


def inv(tmp_path: Path, body: str):
    path = tmp_path / "inv.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return load_inventory(path)


def edge(source: str, target: str, protocol: str = "ssh", port: int = 22, host: str | None = None):
    endpoint = Endpoint(hostname=host or f"{target}.example", port=port, protocol=protocol)
    if protocol == "rdp":
        return RouteEdge(source=source, target=target, interactive=endpoint)
    return RouteEdge(source=source, target=target, automation=endpoint)


# --------------------------------------------------------------------------
# Endpoints and mandatory ports
# --------------------------------------------------------------------------


class TestEndpoints:
    def test_port_is_mandatory(self) -> None:
        """Defaulting a port is how a connection silently goes to the wrong place."""
        with pytest.raises(ConfigError, match="port: required"):
            Endpoint.parse({"hostname": "h.example", "protocol": "ssh"}, "routes[0]")

    def test_the_error_names_what_the_default_would_have_been(self) -> None:
        with pytest.raises(ConfigError, match="would be 5985"):
            Endpoint.parse({"hostname": "h", "protocol": "winrm"}, "routes[0]")

    def test_protocol_is_mandatory(self) -> None:
        with pytest.raises(ConfigError, match="protocol: required"):
            Endpoint.parse({"hostname": "h", "port": 22}, "routes[0]")

    def test_hostname_is_mandatory(self) -> None:
        with pytest.raises(ConfigError, match="hostname: required"):
            Endpoint.parse({"port": 22, "protocol": "ssh"}, "routes[0]")

    def test_unknown_protocol_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="not one of"):
            Endpoint.parse({"hostname": "h", "port": 1, "protocol": "telnet"}, "routes[0]")

    def test_out_of_range_port_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="outside 1-65535"):
            Endpoint.parse({"hostname": "h", "port": 99999, "protocol": "ssh"}, "routes[0]")

    def test_loopback_is_treated_as_a_preestablished_forward(self) -> None:
        """`localhost:44001` can only mean a tunnel that already exists.

        Treating it as a real host would connect to the operator's own machine.
        """
        endpoint = Endpoint.parse(
            {"hostname": "localhost", "port": 44001, "protocol": "rdp"}, "routes[0]"
        )
        assert endpoint.preestablished is True

    def test_preestablished_can_be_declared_explicitly(self) -> None:
        endpoint = Endpoint.parse(
            {"hostname": "10.0.0.1", "port": 3389, "protocol": "rdp", "preestablished": True},
            "routes[0]",
        )
        assert endpoint.preestablished is True

    def test_a_normal_address_is_not_preestablished(self) -> None:
        endpoint = Endpoint.parse(
            {"hostname": "10.0.0.1", "port": 22, "protocol": "ssh"}, "routes[0]"
        )
        assert endpoint.preestablished is False


class TestEdgeParsing:
    def test_rdp_cannot_be_an_automation_protocol(self) -> None:
        """RDP carries pixels; declaring it as automation is a config error."""
        with pytest.raises(ConfigError, match="cannot run commands"):
            RouteEdge.parse(
                {
                    "source": "b",
                    "target": "j",
                    "automation": {"hostname": "h", "port": 3389, "protocol": "rdp"},
                },
                "routes[0]",
            )

    def test_inline_rdp_becomes_the_interactive_endpoint(self) -> None:
        parsed = RouteEdge.parse(
            {"source": "b", "target": "j", "hostname": "h", "port": 3389, "protocol": "rdp"},
            "routes[0]",
        )
        assert parsed.interactive is not None
        assert parsed.automation is None
        assert not parsed.automatable

    def test_inline_ssh_becomes_the_automation_endpoint(self) -> None:
        parsed = RouteEdge.parse(
            {"source": "b", "target": "t", "hostname": "h", "port": 22, "protocol": "ssh"},
            "routes[0]",
        )
        assert parsed.automatable

    def test_both_endpoints_can_be_declared(self) -> None:
        parsed = RouteEdge.parse(
            {
                "source": "b",
                "target": "j",
                "interactive": {"hostname": "localhost", "port": 44001, "protocol": "rdp"},
                "automation": {"hostname": "localhost", "port": 45985, "protocol": "winrm"},
            },
            "routes[0]",
        )
        assert parsed.interactive.port == 44001
        assert parsed.automation.port == 45985

    def test_an_edge_with_no_endpoint_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="declare how"):
            RouteEdge.parse({"source": "b", "target": "j"}, "routes[0]")

    def test_source_and_target_are_required(self) -> None:
        with pytest.raises(ConfigError, match="source: required"):
            RouteEdge.parse({"target": "j"}, "routes[0]")
        with pytest.raises(ConfigError, match="target: required"):
            RouteEdge.parse({"source": "b"}, "routes[0]")

    def test_self_loop_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="both 'b'"):
            RouteEdge.parse(
                {"source": "b", "target": "b", "hostname": "h", "port": 22, "protocol": "ssh"},
                "routes[0]",
            )


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


class TestResolution:
    def test_resolves_a_declared_chain(self) -> None:
        graph = RouteGraph.build(
            [
                edge(LOCAL, "bastion1", port=2222),
                edge("bastion1", "jump1", protocol="winrm", port=5985),
                edge("jump1", "app01", protocol="winrm", port=5985),
            ]
        )
        resolved = graph.resolve("app01")
        assert resolved.nodes == (LOCAL, "bastion1", "jump1", "app01")
        assert resolved.hops == ("bastion1", "jump1")
        assert resolved.describe() == "local -> bastion1 -> jump1 -> app01"

    def test_undeclared_target_fails_with_the_specified_error(self) -> None:
        """The exact failure mode the spec asks for."""
        graph = RouteGraph.build([edge(LOCAL, "bastion1", port=2222)])
        with pytest.raises(RouteError) as exc:
            graph.resolve("linux-app01")
        message = str(exc.value)
        assert "No route defined between requested target and available bastion" in message
        assert "linux-app01" in message
        assert "a direct connection will not be attempted" in message

    def test_a_declared_node_with_no_path_back_to_local_fails(self) -> None:
        graph = RouteGraph.build(
            [
                edge(LOCAL, "bastion1", port=2222),
                edge("orphan-jump", "app01", port=22),  # nothing reaches orphan-jump
            ]
        )
        with pytest.raises(RouteError, match="no chain of edges connects it back"):
            graph.resolve("app01")

    def test_shortest_declared_path_wins(self) -> None:
        graph = RouteGraph.build(
            [
                edge(LOCAL, "b1", port=22),
                edge("b1", "j1", port=22),
                edge("j1", "app", port=22),
                edge("b1", "app", port=22),  # shorter
            ]
        )
        assert graph.resolve("app").hops == ("b1",)

    def test_ambiguous_equal_length_paths_are_refused(self) -> None:
        """Traversal must be unambiguous; guessing would be worse than failing."""
        graph = RouteGraph.build(
            [
                edge(LOCAL, "b1", port=22),
                edge(LOCAL, "b2", port=22),
                edge("b1", "app", port=22),
                edge("b2", "app", port=22),
            ]
        )
        with pytest.raises(RouteError, match="ambiguous route"):
            graph.resolve("app")

    def test_local_is_not_a_target(self) -> None:
        with pytest.raises(RouteError, match="operator's machine"):
            RouteGraph.build([]).resolve(LOCAL)

    def test_duplicate_edges_are_rejected(self) -> None:
        with pytest.raises(ConfigError, match="duplicate route"):
            RouteGraph.build([edge(LOCAL, "b1"), edge(LOCAL, "b1")])

    def test_entry_points_are_only_those_declared_from_local(self) -> None:
        graph = RouteGraph.build(
            [edge(LOCAL, "b1", port=22), edge(LOCAL, "b2", port=22), edge("b1", "app", port=22)]
        )
        assert sorted(graph.entry_points()) == ["b1", "b2"]

    def test_an_interactive_only_final_hop_cannot_be_automated(self) -> None:
        graph = RouteGraph.build(
            [edge(LOCAL, "b1", port=22), edge("b1", "jump", protocol="rdp", port=3389)]
        )
        with pytest.raises(RouteError, match="RDP cannot run commands"):
            graph.resolve("jump", require_automation=True)
        # ...but a human may still be handed the session.
        assert graph.resolve("jump", require_automation=False).hops == ("b1",)

    def test_an_interactive_only_intermediate_hop_is_refused(self) -> None:
        """A hop has to run commands for the next leg to be launched from it."""
        graph = RouteGraph.build(
            [
                edge(LOCAL, "b1", port=22),
                edge("b1", "jump", protocol="rdp", port=3389),
                edge("jump", "app", protocol="winrm", port=5985),
            ]
        )
        with pytest.raises(RouteError, match="rdp-only"):
            graph.resolve("app")


class TestEnvironmentBoundaries:
    def _graph(self, env_a: str, env_b: str) -> RouteGraph:
        return RouteGraph.build(
            [edge(LOCAL, "bastion", port=22), edge("bastion", "app", port=22)],
            contexts={
                "bastion": NetworkContext(environment=env_a),
                "app": NetworkContext(environment=env_b),
            },
        )

    def test_same_environment_traverses(self) -> None:
        assert self._graph("QA", "QA").resolve("app").hops == ("bastion",)

    def test_crossing_environments_is_refused(self) -> None:
        """A QA bastion must not become a path into production."""
        with pytest.raises(RouteError, match="crosses an environment boundary"):
            self._graph("QA", "PROD").resolve("app")

    def test_the_error_names_both_environments(self) -> None:
        with pytest.raises(RouteError) as exc:
            self._graph("QA", "PROD").resolve("app")
        assert "QA" in str(exc.value) and "PROD" in str(exc.value)

    def test_missing_context_does_not_block_traversal(self) -> None:
        assert self._graph("", "").resolve("app").hops == ("bastion",)

    def test_environment_comparison_is_case_insensitive(self) -> None:
        assert self._graph("qa", "QA").resolve("app").hops == ("bastion",)


# --------------------------------------------------------------------------
# Declaration styles, end to end through the config loader
# --------------------------------------------------------------------------


class TestDeclarationStyles:
    def test_explicit_routes_are_used_when_present(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hops:
              bastion1: {role: bastion, kind: ssh, hostname: b.example, port: 2222, username: u}
              jump1: {role: jump, kind: windows, hostname: localhost, username: u, domain: corp}
            hosts:
              app01: {role: target, kind: windows, hostname: 10.0.0.5, username: u, domain: corp}
            routes:
              - {source: local, target: bastion1, hostname: b.example, port: 2222, protocol: ssh}
              - source: bastion1
                target: jump1
                interactive: {hostname: localhost, port: 44001, protocol: rdp}
                automation: {hostname: localhost, port: 45985, protocol: winrm}
              - source: jump1
                target: app01
                automation: {hostname: 10.0.0.5, port: 5985, protocol: winrm}
            """,
        )
        assert inventory.routes_declared
        route = plan_route(inventory, "app01")
        assert route.channel == CHANNEL_NESTED_WINRM
        assert [leg.id for leg in route.legs] == ["bastion1", "jump1", "app01"]

    def test_the_preestablished_forward_is_carried_through(self, tmp_path: Path) -> None:
        """localhost:44001 from the reference config must survive to the leg."""
        inventory = inv(
            tmp_path,
            """
            hops:
              bastion1: {role: bastion, kind: ssh, hostname: b.example, port: 2222, username: u}
              jump1: {role: jump, kind: windows, hostname: localhost, username: u}
            hosts:
              app01: {role: target, kind: windows, hostname: 10.0.0.5, username: u}
            routes:
              - {source: local, target: bastion1, hostname: b.example, port: 2222, protocol: ssh}
              - source: bastion1
                target: jump1
                interactive: {hostname: localhost, port: 44001, protocol: rdp}
                automation: {hostname: localhost, port: 45985, protocol: winrm}
              - source: jump1
                target: app01
                automation: {hostname: 10.0.0.5, port: 5985, protocol: winrm}
            """,
        )
        jump_leg = plan_route(inventory, "app01").leg_for("jump1")
        assert jump_leg is not None
        assert jump_leg.endpoint.preestablished is True
        assert jump_leg.endpoint.port == 45985
        assert jump_leg.interactive is not None and jump_leg.interactive.port == 44001

    def test_path_shorthand_compiles_to_the_same_graph(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hops:
              b1: {kind: ssh, hostname: b.example, port: 2222, username: u}
            hosts:
              app: {kind: linux, hostname: 10.0.0.9, path: [b1], username: u}
            """,
        )
        assert not inventory.routes_declared
        assert plan_route(inventory, "app").channel == CHANNEL_SSH
        assert inventory.graph.entry_points() == ["b1"]

    def test_shared_bastion_edges_are_deduplicated(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hops:
              b1: {kind: ssh, hostname: b.example, port: 2222, username: u}
            hosts:
              a: {kind: linux, hostname: 10.0.0.1, path: [b1], username: u}
              c: {kind: linux, hostname: 10.0.0.2, path: [b1], username: u}
            """,
        )
        local_edges = [e for e in inventory.graph.edges if e.source == "local"]
        assert len(local_edges) == 1

    def test_a_route_naming_an_undeclared_node_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not defined under 'hops:' or 'hosts:'"):
            inv(
                tmp_path,
                """
                hosts:
                  app: {kind: linux, hostname: 10.0.0.1, username: u}
                routes:
                  - {source: local, target: ghost, hostname: g, port: 22, protocol: ssh}
                  - {source: ghost, target: app, hostname: 10.0.0.1, port: 22, protocol: ssh}
                """,
            )

    def test_an_unroutable_host_fails_at_load_time(self, tmp_path: Path) -> None:
        """Fail fast: before the operator has typed a single password."""
        with pytest.raises(ConfigError, match="unroutable hosts"):
            inv(
                tmp_path,
                """
                hops:
                  b1: {kind: ssh, hostname: b.example, port: 2222, username: u}
                hosts:
                  stranded: {kind: linux, hostname: 10.0.0.1, username: u}
                routes:
                  - {source: local, target: b1, hostname: b.example, port: 2222, protocol: ssh}
                """,
            )


# --------------------------------------------------------------------------
# Domain awareness
# --------------------------------------------------------------------------


class TestDomainAwareness:
    def test_bare_username_is_qualified(self) -> None:
        assert qualify_username("jumpuser", "corp") == "corp\\jumpuser"

    def test_an_already_qualified_name_is_left_alone(self) -> None:
        assert qualify_username("CORP\\me", "corp") == "CORP\\me"
        assert qualify_username("me@corp.net", "corp") == "me@corp.net"

    def test_no_domain_means_no_change(self) -> None:
        assert qualify_username("jumpuser", "") == "jumpuser"
        assert qualify_username("jumpuser", None) == "jumpuser"

    def test_none_username_passes_through(self) -> None:
        assert qualify_username(None, "corp") is None

    def test_nodes_expose_a_qualified_identity(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hops:
              b1: {kind: ssh, hostname: b.example, port: 2222, username: operator, domain: corp}
            hosts:
              app:
                kind: windows
                hostname: 10.0.0.5
                username: jumpuser
                domain: corp
                path: [b1]
            """,
        )
        # Every kind qualifies: Windows auth needs it, and AD-joined Unix hosts
        # (SSSD, winbind, Centrify) accept DOMAIN\user over SSH too. A node that
        # wants a bare name omits `domain:`.
        assert inventory.hop("b1").qualified_user == "corp\\operator"
        assert inventory.get("app").qualified_user == "corp\\jumpuser"

    def test_no_domain_means_a_bare_login_name(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hops:
              b1: {kind: ssh, hostname: b.example, port: 2222, username: operator}
            hosts:
              app: {kind: linux, hostname: 10.0.0.5, username: gis, path: [b1]}
            """,
        )
        assert inventory.hop("b1").qualified_user == "operator"

    def test_a_upn_username_on_an_ssh_node_is_allowed(self, tmp_path: Path) -> None:
        """`user@realm` is legitimate for SSH; only the backslash form is not."""
        inventory = inv(
            tmp_path,
            """
            hops:
              b1: {kind: ssh, hostname: b.example, port: 2222, username: operator@corp.net}
            hosts:
              app: {kind: linux, hostname: 10.0.0.5, username: gis, path: [b1]}
            """,
        )
        assert inventory.hop("b1").qualified_user == "operator@corp.net"

    def test_a_username_that_contradicts_its_domain_is_rejected(self, tmp_path: Path) -> None:
        """Two domains, one login. Refuse rather than silently pick a winner."""
        with pytest.raises(ConfigError, match="already carries the domain 'prod'"):
            inv(
                tmp_path,
                """
                hosts:
                  app:
                    kind: windows
                    hostname: 10.0.0.5
                    username: 'prod\\operator'
                    domain: corp
                    path: []
                    vars: {allow_direct: true}
                """,
            )

    def test_a_upn_that_contradicts_its_domain_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="already carries the domain 'prod'"):
            inv(
                tmp_path,
                """
                hosts:
                  app:
                    kind: windows
                    hostname: 10.0.0.5
                    username: operator@prod.example.com
                    domain: corp
                    path: []
                    vars: {allow_direct: true}
                """,
            )

    def test_a_username_that_agrees_with_its_domain_is_fine(self, tmp_path: Path) -> None:
        """Redundant, but not contradictory -- and case must not matter."""
        inventory = inv(
            tmp_path,
            """
            hosts:
              app:
                kind: windows
                hostname: 10.0.0.5
                username: 'CORP\\jumpuser'
                domain: corp
                path: []
                vars: {allow_direct: true}
            """,
        )
        assert inventory.get("app").qualified_user == "CORP\\jumpuser"

    def test_a_qualified_username_with_no_domain_field_is_fine(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hosts:
              app:
                kind: windows
                hostname: 10.0.0.5
                username: 'CORP\\opuser'
                path: []
                vars: {allow_direct: true}
            """,
        )
        assert inventory.get("app").qualified_user == "CORP\\opuser"

    def test_a_windows_host_reached_over_ssh_still_qualifies(self, tmp_path: Path) -> None:
        inventory = inv(
            tmp_path,
            """
            hops:
              b1: {kind: ssh, hostname: b.example, port: 2222, username: operator}
            hosts:
              app:
                kind: windows
                automation: ssh
                hostname: 10.0.0.5
                username: jumpuser
                domain: corp
                path: [b1]
            """,
        )
        assert inventory.get("app").qualified_user == "corp\\jumpuser"


# --------------------------------------------------------------------------
# Context, identity and logging
# --------------------------------------------------------------------------


class TestNetworkContext:
    def test_parses_both_spellings_of_network_zone(self) -> None:
        assert NetworkContext.parse({"networkZone": "DMZ"}).network_zone == "DMZ"
        assert NetworkContext.parse({"network_zone": "DMZ"}).network_zone == "DMZ"

    def test_describe_omits_empty_fields(self) -> None:
        assert NetworkContext(environment="QA").describe() == "env=QA"
        assert NetworkContext().describe() == "(no context)"

    def test_unknown_keys_are_preserved(self) -> None:
        context = NetworkContext.parse({"environment": "QA", "costCentre": "1234"})
        assert context.extra["costCentre"] == "1234"
        assert context.to_dict()["costCentre"] == "1234"


class TestAgentIdentity:
    def test_ids_follow_the_declared_shape(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("AC_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("AC_AGENT_ID", raising=False)
        identity = AgentIdentity.create()
        assert identity.agent_id.startswith("AGT-")
        assert len(identity.agent_id.split("-")) == 3
        assert identity.session_id.startswith("SES-")
        assert len(identity.session_id) == len("SES-000001")

    def test_each_run_gets_a_distinct_identity(self, tmp_path: Path, monkeypatch) -> None:
        """Concurrent runs must be separable in the trail."""
        monkeypatch.setenv("AC_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("AC_AGENT_ID", raising=False)
        ids = {AgentIdentity.create().agent_id for _ in range(3)}
        sessions = {AgentIdentity.create().session_id for _ in range(3)}
        assert len(ids) == 3
        assert len(sessions) == 3

    def test_an_explicit_agent_id_is_honoured(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("AC_DATA_DIR", str(tmp_path))
        assert AgentIdentity.create(agent_id="AGT-CUSTOM").agent_id == "AGT-CUSTOM"

    def test_trace_id_is_sortable_and_filename_safe(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("AC_DATA_DIR", str(tmp_path))
        trace = AgentIdentity.create().trace_id
        assert "/" not in trace and "\\" not in trace and ":" not in trace


class TestLoggingConfig:
    def test_defaults(self) -> None:
        config = LoggingConfig.parse(None)
        assert config.enabled and config.retention_days == 30 and config.level == "INFO"

    def test_parses_both_spellings_of_retention(self) -> None:
        assert LoggingConfig.parse({"retentionDays": 7}).retention_days == 7
        assert LoggingConfig.parse({"retention_days": 7}).retention_days == 7

    def test_invalid_level_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="not one of"):
            LoggingConfig.parse({"level": "CHATTY"})

    def test_negative_retention_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="zero or positive"):
            LoggingConfig.parse({"retention_days": -1})

    def test_configured_path_is_used(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("AC_LOG_DIR", raising=False)
        target = tmp_path / "agent-logs"
        assert LoggingConfig.parse({"path": str(target)}).resolve_directory() == target
        assert target.exists()

    def test_env_override_wins(self, tmp_path: Path, monkeypatch) -> None:
        override = tmp_path / "override"
        monkeypatch.setenv("AC_LOG_DIR", str(override))
        assert LoggingConfig.parse({"path": str(tmp_path / "ignored")}).resolve_directory() == override

    def test_retention_prunes_old_trails_only(self, tmp_path: Path) -> None:
        import os
        import time

        old = tmp_path / "old.jsonl"
        fresh = tmp_path / "fresh.jsonl"
        old.write_text("{}", encoding="utf-8")
        fresh.write_text("{}", encoding="utf-8")
        ancient = time.time() - (40 * 86400)
        os.utime(old, (ancient, ancient))

        removed = LoggingConfig(retention_days=30).prune(tmp_path)
        assert "old.jsonl" in removed
        assert fresh.exists() and not old.exists()

    def test_zero_retention_keeps_everything(self, tmp_path: Path) -> None:
        import os
        import time

        old = tmp_path / "old.jsonl"
        old.write_text("{}", encoding="utf-8")
        ancient = time.time() - (400 * 86400)
        os.utime(old, (ancient, ancient))
        assert LoggingConfig(retention_days=0).prune(tmp_path) == []
        assert old.exists()
