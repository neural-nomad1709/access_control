"""F-07: ``ac tunnel --port`` must reach the transport as ``local_port``.

Both CLI paths -- attached to a running daemon, and the ephemeral fallback --
historically dropped the requested port on the floor and let the OS pick one.
These tests drive the real ``tunnel`` command through typer and capture the
arguments at the session boundary, which is where the defect lives; the
session/daemon/transport layers underneath have their own real-socket tests.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from access_control import cli

REQUESTED_PORT = 45123


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
                host: 127.0.0.1
                port: 22
                user: opuser
                description: Test bastion
                auth:
                  method: password

            hosts:
              app01:
                kind: linux
                host: 10.0.0.101
                port: 22
                path: [bastion1]
                user: opuser
                description: Test application server
                auth:
                  method: password
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AC_CONFIG_DIR", str(directory))
    return directory


@pytest.fixture(autouse=True)
def quiet_hold(monkeypatch: pytest.MonkeyPatch) -> None:
    """``tunnel`` blocks holding the forward open; skip that in tests."""
    monkeypatch.setattr(cli, "_hold_tunnel", lambda *a, **k: None)


class RecordingClient:
    """Stands in for a daemon SessionClient; records what the CLI asks for."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, method: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, kwargs))
        if method == "open_tunnel":
            return {
                "tunnel_id": 1,
                "local_host": "127.0.0.1",
                "local_port": kwargs.get("local_port") or 55000,
                "dest": f"{kwargs['dest_host']}:{kwargs['dest_port']}",
            }
        return {}


class RecordingForward:
    def __init__(self, local_port: int) -> None:
        self.local_port = local_port
        self.endpoint = f"127.0.0.1:{local_port}"


class RecordingSession:
    def __init__(self) -> None:
        self.open_tunnel_kwargs: dict[str, Any] | None = None

    def open_tunnel(
        self, dest_host: str, dest_port: int, purpose: str = "", local_port: int = 0
    ) -> RecordingForward:
        self.open_tunnel_kwargs = {
            "dest_host": dest_host,
            "dest_port": dest_port,
            "purpose": purpose,
            "local_port": local_port,
        }
        return RecordingForward(local_port or 55000)


class RecordingEphemeral:
    """Context manager matching EphemeralSession's shape."""

    last_session: RecordingSession | None = None

    def __init__(self, host_id: str, **kwargs: Any) -> None:
        self.host_id = host_id

    def __enter__(self) -> RecordingSession:
        session = RecordingSession()
        RecordingEphemeral.last_session = session
        return session

    def __exit__(self, *exc: object) -> None:
        return None


class TestTunnelPortPropagation:
    def test_attached_path_passes_requested_port(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = RecordingClient()
        monkeypatch.setattr(cli, "attach", lambda node: client)

        result = CliRunner().invoke(
            cli.app, ["tunnel", "app01", "--port", str(REQUESTED_PORT)]
        )

        assert result.exit_code == 0, result.output
        methods = [m for m, _ in client.calls]
        assert "open_tunnel" in methods
        kwargs = dict(client.calls)[("open_tunnel")]
        assert kwargs.get("local_port") == REQUESTED_PORT

    def test_ephemeral_path_passes_requested_port(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", RecordingEphemeral)

        result = CliRunner().invoke(
            cli.app, ["tunnel", "app01", "--port", str(REQUESTED_PORT)]
        )

        assert result.exit_code == 0, result.output
        session = RecordingEphemeral.last_session
        assert session is not None and session.open_tunnel_kwargs is not None
        assert session.open_tunnel_kwargs["local_port"] == REQUESTED_PORT

    def test_a_busy_port_is_a_clear_error_not_a_silent_substitute(self) -> None:
        """The documented contract: a requested port that cannot be bound raises
        ConnectionFailed. On Windows a plain SO_REUSEADDR bind can silently
        steal a port another process is listening on, so this proves the
        exclusive-bind behaviour on every platform CI runs."""
        import socket

        from access_control.errors import ConnectionFailed
        from access_control.transport.tunnel import LocalTunnel

        occupant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupant.bind(("127.0.0.1", 0))
        occupant.listen(1)
        busy_port = occupant.getsockname()[1]
        try:
            tunnel = LocalTunnel(None, "10.0.0.99", 22, local_port=busy_port)
            with pytest.raises(ConnectionFailed):
                tunnel.start()
        finally:
            occupant.close()

    def test_no_misleading_unavailable_note_when_port_is_honoured(
        self, config_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(cli, "attach", lambda node: None)
        monkeypatch.setattr(cli, "EphemeralSession", RecordingEphemeral)

        result = CliRunner().invoke(
            cli.app, ["tunnel", "app01", "--port", str(REQUESTED_PORT)]
        )

        assert result.exit_code == 0, result.output
        assert "unavailable" not in result.output
