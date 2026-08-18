"""Inventory and operation-catalog loading, validation, and host binding."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from access_control.config import (
    Catalog,
    Inventory,
    load_inventory,
    load_operations,
    operation_variables,
    unresolved_variables,
    validate_catalog_against_inventory,
)
from access_control.errors import ConfigError


def write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class TestInventory:
    def test_loads_hops_and_hosts(self, inventory: Inventory) -> None:
        assert set(inventory.hops) == {"bastion1", "jump1"}
        assert set(inventory.hosts) == {"lin01", "win01", "win02"}

    def test_bastion_auth_is_key_plus_password(self, inventory: Inventory) -> None:
        auth = inventory.hop("bastion1").auth
        assert auth.method == "key+password"
        assert auth.uses_key and auth.uses_password
        assert auth.key_file is not None and auth.key_file.name == "id_test"

    def test_key_file_is_expanded(self, inventory: Inventory) -> None:
        key_file = inventory.hop("bastion1").auth.key_file
        assert key_file is not None
        assert "~" not in str(key_file)

    def test_windows_defaults(self, inventory: Inventory) -> None:
        jump = inventory.hop("jump1")
        assert jump.is_windows
        assert jump.automation == "winrm"
        assert jump.winrm_port == 5985
        assert jump.rdp_port == 3389

    def test_host_vars_are_available(self, inventory: Inventory) -> None:
        assert inventory.get("win01").vars["patch_share"] == "D:\\packages\\patches"

    def test_node_finds_hops_and_hosts(self, inventory: Inventory) -> None:
        assert inventory.node("jump1").id == "jump1"
        assert inventory.node("win01").id == "win01"

    def test_unknown_host_names_the_alternatives(self, inventory: Inventory) -> None:
        with pytest.raises(ConfigError, match="unknown host 'nope'.*win01"):
            inventory.get("nope")

    def test_path_referencing_unknown_hop_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hops: {}
            hosts:
              h1:
                host: 10.0.0.1
                path: [ghost]
            """,
        )
        with pytest.raises(ConfigError, match="unknown hop 'ghost'"):
            load_inventory(path)

    def test_empty_path_requires_explicit_opt_in(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              direct:
                host: 10.0.0.1
                path: []
            """,
        )
        with pytest.raises(ConfigError, match="bypassing every bastion"):
            load_inventory(path)

    def test_empty_path_allowed_when_declared(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              direct:
                host: 10.0.0.1
                path: []
                vars:
                  allow_direct: true
            """,
        )
        assert load_inventory(path).get("direct").path == ()

    def test_duplicate_hop_in_path_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hops:
              b:
                host: b.example
            hosts:
              h:
                host: 10.0.0.1
                path: [b, b]
            """,
        )
        with pytest.raises(ConfigError, match="more than once"):
            load_inventory(path)

    def test_host_id_must_match_its_key(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                host_id: something-else
                host: 10.0.0.1
                path: []
                vars: {allow_direct: true}
            """,
        )
        with pytest.raises(ConfigError, match="does not match its key"):
            load_inventory(path)

    def test_rdp_on_a_linux_host_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: linux
                host: 10.0.0.1
                interactive: rdp
                path: []
                vars: {allow_direct: true}
            """,
        )
        with pytest.raises(ConfigError, match="'rdp' requires a windows kind"):
            load_inventory(path)

    def test_winrm_on_a_linux_host_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: linux
                host: 10.0.0.1
                automation: winrm
                path: []
                vars: {allow_direct: true}
            """,
        )
        with pytest.raises(ConfigError, match="only valid for windows nodes"):
            load_inventory(path)

    def test_key_method_without_key_file_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                host: 10.0.0.1
                path: []
                vars: {allow_direct: true}
                auth:
                  method: key
            """,
        )
        with pytest.raises(ConfigError, match="requires 'key_file'"):
            load_inventory(path)

    def test_via_and_routes_compile_to_the_same_graph(self, tmp_path: Path) -> None:
        """The two spellings are one graph, so `via:` inherits every guarantee."""
        via = write(
            tmp_path,
            "via.yaml",
            """
            hops:
              b:
                kind: ssh
                username: opsuser
                domain: corp
                description: entry
                via: {from: local, hostname: b.example, port: 2222, protocol: ssh}
            hosts:
              h1:
                kind: linux
                username: appuser
                domain: corp
                description: target
                via: {from: b, hostname: 10.0.0.1, port: 22, protocol: ssh}
            """,
        )
        routes = write(
            tmp_path,
            "routes.yaml",
            """
            hops:
              b:
                kind: ssh
                host: b.example
                port: 2222
                username: opsuser
                domain: corp
                description: entry
            hosts:
              h1:
                kind: linux
                host: 10.0.0.1
                username: appuser
                domain: corp
                description: target
            routes:
              - {source: local, target: b, hostname: b.example, port: 2222,
                 protocol: ssh, domain: corp, username: opsuser, description: entry}
              - {source: b, target: h1, hostname: 10.0.0.1, port: 22,
                 protocol: ssh, domain: corp, username: appuser, description: target}
            """,
        )
        from_via = [e.to_dict() for e in load_inventory(via).graph.edges]
        from_routes = [e.to_dict() for e in load_inventory(routes).graph.edges]
        assert from_via == from_routes

    def test_via_takes_identity_from_the_node(self, tmp_path: Path) -> None:
        """The edge cannot disagree with the machine, because it never restates it."""
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: windows
                username: jumpuser
                domain: CORP
                via:
                  from: local
                  automation:  {hostname: 10.0.0.1, port: 5985, protocol: winrm}
                  interactive: {hostname: 10.0.0.1, port: 3389, protocol: rdp}
            """,
        )
        edge = load_inventory(path).graph.edges[0]
        assert (edge.domain, edge.username) == ("CORP", "jumpuser")

    def test_via_supplies_the_hostname_and_ports(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: windows
                via:
                  from: local
                  automation:  {hostname: 10.0.0.1, port: 5985, protocol: winrm}
                  interactive: {hostname: 10.0.0.1, port: 3390, protocol: rdp}
            """,
        )
        host = load_inventory(path).get("h1")
        assert host.host == "10.0.0.1"
        assert (host.winrm_port, host.rdp_port) == (5985, 3390)

    def test_via_accepts_a_list_for_two_ways_in(self, tmp_path: Path) -> None:
        """Both legs are declared; the shorter one is what resolution takes.

        Two ways in of *equal* length stay ambiguous and are refused, as they
        always were -- a list declares alternatives, it does not license guessing.
        """
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hops:
              b1: {via: {from: local, hostname: b1.example, port: 22, protocol: ssh}}
              b2: {via: {from: b1, hostname: b2.example, port: 22, protocol: ssh}}
            hosts:
              h1:
                kind: linux
                via:
                  - {from: b1, hostname: 10.0.0.1, port: 22, protocol: ssh}
                  - {from: b2, hostname: 10.9.0.1, port: 22, protocol: ssh}
            """,
        )
        inventory = load_inventory(path)
        assert {e.source for e in inventory.graph.incoming("h1")} == {"b1", "b2"}
        assert inventory.graph.resolve("h1").nodes == ("local", "b1", "h1")

    def test_two_equal_length_ways_in_stay_ambiguous(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hops:
              b1: {via: {from: local, hostname: b1.example, port: 22, protocol: ssh}}
              b2: {via: {from: local, hostname: b2.example, port: 22, protocol: ssh}}
            hosts:
              h1:
                kind: linux
                via:
                  - {from: b1, hostname: 10.0.0.1, port: 22, protocol: ssh}
                  - {from: b2, hostname: 10.9.0.1, port: 22, protocol: ssh}
            """,
        )
        with pytest.raises(ConfigError, match="ambiguous route"):
            load_inventory(path)

    def test_via_from_an_undeclared_node_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: linux
                via: {from: ghost, hostname: 10.0.0.1, port: 22, protocol: ssh}
            """,
        )
        with pytest.raises(ConfigError, match="not defined under 'hops:' or 'hosts:'"):
            load_inventory(path)

    def test_via_without_from_says_what_is_missing(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: linux
                via: {hostname: 10.0.0.1, port: 22, protocol: ssh}
            """,
        )
        with pytest.raises(ConfigError, match=r"hosts\.h1\.via\.from: required"):
            load_inventory(path)

    def test_declaring_both_via_and_routes_is_rejected(self, tmp_path: Path) -> None:
        """Two sources of truth is the bug this shape exists to remove."""
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hops:
              b:
                via: {from: local, hostname: b.example, port: 22, protocol: ssh}
            hosts:
              h1:
                kind: linux
                host: 10.0.0.1
            routes:
              - {source: b, target: h1, hostname: 10.0.0.1, port: 22, protocol: ssh}
            """,
        )
        with pytest.raises(ConfigError, match="connectivity is declared twice"):
            load_inventory(path)

    def test_node_without_hostname_or_via_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: linux
            """,
        )
        with pytest.raises(ConfigError, match="missing required field 'hostname'"):
            load_inventory(path)

    def test_missing_file_explains_how_to_create_it(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="config file not found"):
            load_inventory(tmp_path / "absent.yaml")

    def test_malformed_yaml_is_reported_with_the_path(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("hosts: [unclosed\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="not valid YAML"):
            load_inventory(path)


class TestOperations:
    def test_loads_catalog(self, catalog: Catalog) -> None:
        assert set(catalog.operations) == {
            "echo-op",
            "needs-approval",
            "failing-op",
            "windows-only",
        }

    def test_gating_defaults_to_required(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: unspecified
                host_ids: ['*']
                steps:
                  - id: s
                    run: whoami
            """,
        )
        assert load_operations(path).get("unspecified").is_gated

    def test_operation_must_declare_its_hosts(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: unbound
                steps:
                  - id: s
                    run: whoami
            """,
        )
        with pytest.raises(ConfigError, match="must declare 'host_ids'"):
            load_operations(path)

    def test_operation_without_steps_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: hollow
                host_ids: ['*']
                steps: []
            """,
        )
        with pytest.raises(ConfigError, match="has no steps"):
            load_operations(path)

    def test_duplicate_step_ids_are_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: dup
                host_ids: ['*']
                steps:
                  - id: same
                    run: a
                  - id: same
                    run: b
            """,
        )
        with pytest.raises(ConfigError, match="duplicate step id 'same'"):
            load_operations(path)

    def test_unknown_expectation_key_is_rejected(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: typo
                host_ids: ['*']
                steps:
                  - id: s
                    run: a
                    expect:
                      stdout_contain: oops
            """,
        )
        with pytest.raises(ConfigError, match="unknown expectation key"):
            load_operations(path)

    def test_destructive_step_marks_the_operation(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: op
                host_ids: ['*']
                requires_permission: false
                steps:
                  - id: s
                    run: a
                    destructive: true
            """,
        )
        op = load_operations(path).get("op")
        assert op.destructive and op.is_gated


class TestHostBinding:
    def test_wildcard_applies_everywhere(self, inventory: Inventory, catalog: Catalog) -> None:
        assert catalog.get("echo-op").applies_to(inventory.get("lin01"))
        assert catalog.get("echo-op").applies_to(inventory.get("win01"))

    def test_explicit_host_id_binding(self, inventory: Inventory, catalog: Catalog) -> None:
        op = catalog.get("needs-approval")
        assert op.applies_to(inventory.get("win01"))
        assert not op.applies_to(inventory.get("lin01"))

    def test_tag_binding(self, inventory: Inventory, catalog: Catalog) -> None:
        op = catalog.get("windows-only")
        assert op.applies_to(inventory.get("win01"))
        assert op.applies_to(inventory.get("win02"))
        assert not op.applies_to(inventory.get("lin01"))

    def test_for_host_filters(self, inventory: Inventory, catalog: Catalog) -> None:
        ids = {op.id for op in catalog.for_host(inventory.get("lin01"))}
        assert ids == {"echo-op", "failing-op"}

    def test_unknown_host_id_in_catalog_is_an_error(
        self, inventory: Inventory, tmp_path: Path
    ) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: op
                host_ids: [does-not-exist]
                steps:
                  - id: s
                    run: a
            """,
        )
        catalog = load_operations(path)
        with pytest.raises(ConfigError, match="targets unknown host_id"):
            validate_catalog_against_inventory(catalog, inventory)

    def test_unknown_tag_is_only_a_warning(self, inventory: Inventory, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "ops.yaml",
            """
            operations:
              - id: op
                tags: [nonexistent]
                steps:
                  - id: s
                    run: a
            """,
        )
        warnings = validate_catalog_against_inventory(load_operations(path), inventory)
        assert any("nonexistent" in w for w in warnings)


class TestVariables:
    def test_host_fields_are_available(self, inventory: Inventory, catalog: Catalog) -> None:
        variables = operation_variables(
            catalog.get("echo-op"), inventory.get("win01"), {"message": "hi"}
        )
        assert variables["host_id"] == "win01"
        assert variables["host"] == "10.0.0.30"
        assert variables["patch_share"] == "D:\\packages\\patches"
        assert variables["message"] == "hi"

    def test_package_share_on_a_host_is_rejected(self, tmp_path: Path) -> None:
        """A path the job works on is not a fact about the machine."""
        path = write(
            tmp_path,
            "inv.yaml",
            """
            hosts:
              h1:
                kind: windows
                package_share: 'D:\\packages'
                via: {from: local, hostname: 10.0.0.1, port: 5985, protocol: winrm}
            """,
        )
        with pytest.raises(ConfigError, match="paths belong to the job, not the machine"):
            load_inventory(path)

    def test_missing_required_param_is_named(
        self, inventory: Inventory, catalog: Catalog
    ) -> None:
        with pytest.raises(ConfigError, match="requires parameter\\(s\\): message"):
            operation_variables(catalog.get("echo-op"), inventory.get("win01"), {})

    def test_params_override_host_vars(self, inventory: Inventory, catalog: Catalog) -> None:
        variables = operation_variables(
            catalog.get("echo-op"), inventory.get("win01"), {"message": "x", "host": "override"}
        )
        assert variables["host"] == "override"

    def test_unresolved_variables_are_listed(
        self, inventory: Inventory, catalog: Catalog
    ) -> None:
        op = catalog.get("echo-op")
        assert unresolved_variables(op, {"host_id": "win01"}) == ["message"]
