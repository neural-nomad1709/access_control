"""F-10: ``ac shell`` and ``ac rdp`` must dial the address the route declares.

A node's own ``hostname:`` is a convenience default; the address that is valid
from the hop before it lives on the resolved route leg. ``ac tunnel`` always used
the leg. These tests give the node an address that differs from its leg and
capture what reaches the session boundary on both the attached and the
ephemeral path.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from access_control import cli

from test_cli_tunnel import RecordingClient, RecordingEphemeral


@pytest.fixture
def config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "config"
    directory.mkdir()
    (directory / "inventory.yaml").write_text(
        textwrap.dedent(
            """
            hops:
              bastion1:
                kind: ssh
                username: opuser
                description: Test bastion
                auth: {method: password}
                via: {from: local, hostname: 127.0.0.1, port: 22, protocol: ssh}

            hosts:
              linux-app01:
                kind: linux
                hostname: stale-name.example
                username: appuser
                description: Node address differs from its leg
                auth: {method: password}
                via: {from: bastion1, hostname: 10.0.0.101, port: 2222, protocol: ssh}

              win-app01:
                kind: windows
                username: winuser
                description: RDP is published on a different address than WinRM
                auth: {method: password}
                via:
                  from: bastion1
                  automation:  {hostname: 10.0.0.201, port: 5985, protocol: winrm}
                  interactive: {hostname: 10.0.0.202, port: 3390, protocol: rdp}
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AC_CONFIG_DIR", str(directory))
    return directory


@pytest.fixture(autouse=True)
def no_clients(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    """Record the interactive launches instead of starting ssh or mstsc."""
    launches: list[tuple[Any, ...]] = []
    monkeypatch.setattr(cli, "launch_ssh_shell", lambda *a, **k: launches.append(a))
    monkeypatch.setattr(cli, "_run_rdp", lambda *a, **k: launches.append(a))
    return launches


def _tunnel_dest(client: RecordingClient) -> tuple[str, int]:
    kwargs = dict(client.calls)["open_tunnel"]
    return kwargs["dest_host"], kwargs["dest_port"]


class TestShellUsesTheRouteLeg:
    def test_attached(self, config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        client = RecordingClient()
        monkeypatch.setattr(cli, "attach", lambda node: client)

        result = CliRunner().invoke(cli.app, ["shell", "linux-app01"])

        assert result.exit_code == 0, result.output
        assert _tunnel_dest(client) == ("10.0.0.101", 2222)

    def test_ephemeral(self, config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", RecordingEphemeral)

        result = CliRunner().invoke(cli.app, ["shell", "linux-app01"])

        assert result.exit_code == 0, result.output
        kwargs = RecordingEphemeral.last_session.open_tunnel_kwargs
        assert (kwargs["dest_host"], kwargs["dest_port"]) == ("10.0.0.101", 2222)


class TestRdpUsesTheInteractiveLeg:
    def test_attached(self, config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        client = RecordingClient()
        monkeypatch.setattr(cli, "attach", lambda node: client)

        result = CliRunner().invoke(cli.app, ["rdp", "win-app01"])

        assert result.exit_code == 0, result.output
        assert _tunnel_dest(client) == ("10.0.0.202", 3390)

    def test_ephemeral(self, config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", RecordingEphemeral)

        result = CliRunner().invoke(cli.app, ["rdp", "win-app01"])

        assert result.exit_code == 0, result.output
        kwargs = RecordingEphemeral.last_session.open_tunnel_kwargs
        assert (kwargs["dest_host"], kwargs["dest_port"]) == ("10.0.0.202", 3390)
