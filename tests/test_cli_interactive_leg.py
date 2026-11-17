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
              jump-forwarded:
                kind: windows
                username: winuser
                description: Both endpoints are forwards the operator started
                auth: {method: password}
                via:
                  from: bastion1
                  automation:  {hostname: localhost, port: 45985, protocol: winrm, preestablished: true}
                  interactive: {hostname: localhost, port: 44001, protocol: rdp, preestablished: true}
              jump-winrm-forward-only:
                kind: windows
                username: winuser
                description: Only WinRM was forwarded; nothing carries RDP
                auth: {method: password}
                via: {from: bastion1, hostname: localhost, port: 45986, protocol: winrm}

            hosts:
              linux-forwarded:
                kind: linux
                username: appuser
                description: SSH arrives on a forward the operator started
                auth: {method: password}
                via: {from: bastion1, hostname: localhost, port: 40022, protocol: ssh}

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
    monkeypatch.setenv("AC_DATA_DIR", str(tmp_path / "data"))
    return directory


class FakeRdpSession:
    def wait(self) -> None:
        return None

    def cleanup(self) -> list[str]:
        return []


class RecordingAudit:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any]]] = []

    def action(self, action: str, **fields: Any) -> None:
        self.records.append((action, fields))


class AuditedEphemeral(RecordingEphemeral):
    """An ephemeral session with an audit trail, as the real one has."""

    def __enter__(self) -> Any:
        session = super().__enter__()
        session.audit = RecordingAudit()
        return session


@pytest.fixture(autouse=True)
def launches(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    """Stop at the process boundary: no ssh or mstsc is started. Returns the
    positional arguments each launch was given."""
    seen: list[tuple[Any, ...]] = []

    def ssh(*args: Any, **kwargs: Any) -> None:
        seen.append(("ssh", *args))

    def rdp(*args: Any, **kwargs: Any) -> FakeRdpSession:
        seen.append(("rdp", *args))
        return FakeRdpSession()

    monkeypatch.setattr(cli, "launch_ssh_shell", ssh)
    monkeypatch.setattr(cli, "launch_rdp", rdp)
    return seen


class ForbiddenEphemeral:
    """A pre-established forward needs no session; building one would prompt
    the operator for hop passwords to reach something already reachable."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("no session should be built for a pre-established forward")


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
        monkeypatch.setattr(cli, "EphemeralSession", AuditedEphemeral)

        result = CliRunner().invoke(cli.app, ["rdp", "win-app01"])

        assert result.exit_code == 0, result.output
        kwargs = RecordingEphemeral.last_session.open_tunnel_kwargs
        assert (kwargs["dest_host"], kwargs["dest_port"]) == ("10.0.0.202", 3390)


class TestPreestablishedForward:
    """The forward already exists on this machine: the client is pointed at it
    and nothing is tunnelled. Building a tunnel to ``localhost`` from the bastion
    would reach the bastion itself."""

    def test_rdp_attached_goes_straight_to_the_forward(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch, launches
    ) -> None:
        client = RecordingClient()
        monkeypatch.setattr(cli, "attach", lambda node: client)

        result = CliRunner().invoke(cli.app, ["rdp", "jump-forwarded"])

        assert result.exit_code == 0, result.output
        assert launches == [("rdp", "localhost:44001")]
        methods = [m for m, _ in client.calls]
        assert "open_tunnel" not in methods
        launched = [kw for m, kw in client.calls if m == "rdp_launched"]
        assert launched[0]["endpoint"] == "localhost:44001"

    def test_rdp_without_a_session_builds_none_and_still_audits(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch, launches, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", ForbiddenEphemeral)

        result = CliRunner().invoke(cli.app, ["rdp", "jump-forwarded"])

        assert result.exit_code == 0, result.output
        assert launches == [("rdp", "localhost:44001")]
        trails = list((tmp_path / "data" / "logs").glob("*.jsonl"))
        assert len(trails) == 1
        text = trails[0].read_text(encoding="utf-8")
        assert '"action": "RDP_LAUNCH"' in text and "localhost:44001" in text

    def test_shell_attached_goes_straight_to_the_forward(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch, launches
    ) -> None:
        client = RecordingClient()
        monkeypatch.setattr(cli, "attach", lambda node: client)

        result = CliRunner().invoke(cli.app, ["shell", "linux-forwarded"])

        assert result.exit_code == 0, result.output
        assert launches == [("ssh", "localhost", 40022)]
        assert "open_tunnel" not in [m for m, _ in client.calls]

    def test_shell_without_a_session_builds_none(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch, launches
    ) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", ForbiddenEphemeral)

        result = CliRunner().invoke(cli.app, ["shell", "linux-forwarded"])

        assert result.exit_code == 0, result.output
        assert launches == [("ssh", "localhost", 40022)]

    def test_rdp_is_refused_when_only_another_protocol_was_forwarded(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch, launches
    ) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", ForbiddenEphemeral)

        result = CliRunner().invoke(cli.app, ["rdp", "jump-winrm-forward-only"])

        assert result.exit_code == 1
        assert launches == []
        output = result.output.replace("\n", " ")
        assert "no forward for rdp" in output
        # A loopback leg is pre-established unless it says otherwise, so the
        # way out is an explicit value -- "remove the key" would change nothing.
        assert "preestablished: false" in output

    def test_tunnel_to_a_pre_established_leg_says_how_to_build_one(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch, launches
    ) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", ForbiddenEphemeral)

        result = CliRunner().invoke(cli.app, ["tunnel", "linux-forwarded"])

        assert result.exit_code == 1
        output = result.output.replace("\n", " ")
        assert "nothing for this command to build" in output
        assert "preestablished: false" in output


class TestRdpLaunchIsAudited:
    """F-03: the interactive session itself is recorded, not only its tunnel."""

    def test_attached(self, config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        client = RecordingClient()
        monkeypatch.setattr(cli, "attach", lambda node: client)

        result = CliRunner().invoke(cli.app, ["rdp", "win-app01"])

        assert result.exit_code == 0, result.output
        launched = [kw for m, kw in client.calls if m == "rdp_launched"]
        assert launched == [{
            "node_id": "win-app01",
            "endpoint": "127.0.0.1:55000",
            "username": "winuser",
            "staged": False,
        }]

    def test_ephemeral(self, config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", AuditedEphemeral)

        result = CliRunner().invoke(cli.app, ["rdp", "win-app01"])

        assert result.exit_code == 0, result.output
        audit = AuditedEphemeral.last_session.audit
        records = [f for a, f in audit.records if a == "RDP_LAUNCH"]
        assert len(records) == 1
        assert records[0]["target"] == "win-app01"
        assert records[0]["endpoint"] == "127.0.0.1:55000"
        assert records[0]["credential_staged"] is False
