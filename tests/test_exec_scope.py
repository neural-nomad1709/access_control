"""F-02: a session restricted with ``--ops`` refuses ad-hoc commands.

``--ops`` used to scope catalogue operations only, so ``ac exec`` (and the
``run_command`` protocol method behind it, which ``ac mcp`` exposes) still ran
anything the deny-list let through. A restricted session now refuses ad-hoc
commands unless the operator also passed ``--allow-exec``. ``ac logs`` stays
available: it reads a file, and its path can no longer smuggle a command in.
"""

from __future__ import annotations

import shlex
from typing import Any

import pytest
from typer.testing import CliRunner

from access_control import cli
from access_control.config import load_inventory, load_operations
from access_control.engine import Engine, tail_command
from access_control.errors import AccessControlError, PermissionRequired
from access_control.session import Session

from test_daemon import RunningServer, ServableSession


@pytest.fixture
def real_session(config_files):
    def factory(**kwargs: Any) -> Session:
        return Session(
            inventory=load_inventory(config_files / "inventory.yaml"),
            catalog=load_operations(config_files / "operations.yaml"),
            host_id="lin01",
            **kwargs,
        )

    return factory


class TestSessionScope:
    def test_an_unrestricted_session_permits_ad_hoc_commands(self, real_session) -> None:
        assert real_session().exec_permitted

    def test_ops_without_allow_exec_refuses_them(self, real_session) -> None:
        assert not real_session(allowed_operations=("echo-op",)).exec_permitted

    def test_allow_exec_reopens_them(self, real_session) -> None:
        session = real_session(allowed_operations=("echo-op",), allow_exec=True)
        assert session.exec_permitted

    def test_status_reports_the_scope(self, real_session) -> None:
        session = real_session(allowed_operations=("echo-op",))
        session.channel = object()  # status() reads connection fields only
        assert session.status()["exec_permitted"] is False


class TestEngineRefusal:
    def test_run_command_is_refused_and_audited(self, make_session, audit_log) -> None:
        session = make_session("win01", audit=audit_log, allowed_operations=("echo-op",))
        session.exec_permitted = False

        with pytest.raises(PermissionRequired, match="--allow-exec"):
            Engine(session).run_command("Stop-Service W3SVC")

        assert session.commands == [], "nothing may reach the host"
        blocked = [r for r in audit_log.records if r.get("action") == "COMMAND_BLOCKED"]
        assert len(blocked) == 1 and "Stop-Service W3SVC" in blocked[0]["detail"]

    def test_the_refusal_names_the_reconnect_command(self, make_session) -> None:
        session = make_session("win01", allowed_operations=("echo-op",))
        session.exec_permitted = False
        with pytest.raises(PermissionRequired) as exc:
            Engine(session).run_command("hostname")
        assert "ac connect win01 --ops echo-op --allow-exec" in str(exc.value)

    def test_fetch_log_still_works_in_a_restricted_session(self, make_session) -> None:
        session = make_session("win01", allowed_operations=("echo-op",))
        session.exec_permitted = False
        result = Engine(session).fetch_log("C:\\Windows\\Temp\\*.log", 20)
        assert result.ok and len(session.commands) == 1


class TestDaemonBoundary:
    def test_run_command_is_refused_over_the_protocol(self) -> None:
        session = ServableSession()
        session.allowed_operations = ("echo-op",)
        session.exec_permitted = False
        with RunningServer(session) as (client, _):
            with pytest.raises(AccessControlError, match="--allow-exec"):
                client.call("run_command", command="hostname")
        assert session.commands == []

    def test_fetch_log_is_served_over_the_protocol(self) -> None:
        session = ServableSession()
        session.exec_permitted = False
        with RunningServer(session) as (client, _):
            client.call("fetch_log", path="/var/log/messages", tail=5)
        assert len(session.commands) == 1


class TestWiring:
    def test_build_session_threads_allow_exec_through(self, config_files, monkeypatch) -> None:
        from access_control.daemon import build_session

        monkeypatch.setenv("AC_DATA_DIR", str(config_files.parent / "data"))
        session = build_session(
            "lin01",
            inventory=load_inventory(config_files / "inventory.yaml"),
            catalog=load_operations(config_files / "operations.yaml"),
            allowed_operations=("echo-op",),
            allow_exec=True,
        )
        assert session.exec_permitted

    def test_connect_passes_allow_exec(self, monkeypatch) -> None:
        seen: dict[str, Any] = {}

        def recording_build_session(host: str, **kwargs: Any) -> None:
            seen.update(kwargs)
            raise AccessControlError("stop after recording")

        monkeypatch.setattr(cli, "attach", lambda host: None)
        monkeypatch.setattr(cli, "build_session", recording_build_session)

        CliRunner().invoke(cli.app, ["connect", "lin01", "--ops", "echo-op", "--allow-exec"])
        assert seen["allowed_operations"] == ("echo-op",)
        assert seen["allow_exec"] is True

    def test_connect_defaults_to_no_exec(self, monkeypatch) -> None:
        seen: dict[str, Any] = {}

        def recording_build_session(host: str, **kwargs: Any) -> None:
            seen.update(kwargs)
            raise AccessControlError("stop after recording")

        monkeypatch.setattr(cli, "attach", lambda host: None)
        monkeypatch.setattr(cli, "build_session", recording_build_session)

        CliRunner().invoke(cli.app, ["connect", "lin01", "--ops", "echo-op"])
        assert seen["allow_exec"] is False


HOSTILE = "/tmp/x; touch /tmp/pwned"


class TestLogPathCannotCarryACommand:
    def test_posix_path_is_one_argument(self) -> None:
        tokens = shlex.split(tail_command(HOSTILE, 20, windows=False))
        assert tokens[:4] == ["tail", "-n", "20", HOSTILE]
        assert ";" not in tokens

    def test_posix_message_cannot_break_out_of_its_quotes(self) -> None:
        tokens = shlex.split(tail_command("/tmp/it's'; touch /tmp/pwned; '", 20, windows=False))
        assert tokens[-2] == "echo"
        assert tokens[-1].startswith("no such file or not readable: ")

    def test_posix_glob_still_expands(self) -> None:
        command = tail_command("/var/log/app*.log", 20, windows=False)
        assert "/var/log/app*.log" in command

    def test_windows_path_is_never_inside_a_double_quoted_string(self) -> None:
        hostile = "$(Stop-Service W3SVC)"
        command = tail_command(hostile, 20, windows=True)
        assert command.count(hostile) == command.count(f"'{hostile}'")
