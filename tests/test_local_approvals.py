"""F-01: an agent's ``--confirm`` does not prove a human approved.

Standalone, with no external governance plane: a gated request made by an agent
is held in the session's own approval store until the human types
``:approve <id>`` at the ``ac connect`` prompt. One approval authorizes one run
of exactly the commands that were shown; a request nobody answers lapses into a
denial. A human running ``ac run --confirm`` from a plain terminal is unchanged.

A request counts as an agent's when the session was opened as agent-attached
(``--agent-id`` / ``AC_AGENT_ID`` / connect inside an agent harness) or when the
client command itself runs inside an agent harness (``agent_caller``).
"""

from __future__ import annotations

import io
import textwrap
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from typer.testing import CliRunner

from access_control import cli
from access_control.config import load_inventory, load_operations
from access_control.engine import Engine
from access_control.errors import PermissionRequired
from access_control.gatekeeper import LocalGatekeeper
from access_control.operator_shell import OperatorShell
from access_control.transport.base import ExecResult

from conftest import FakeSession

OPERATIONS = """
operations:
  - id: gated-op
    description: Needs approval
    host_ids: ['*']
    requires_permission: true
    steps:
      - id: only
        desc: Harmless, but gated by the catalogue
        run: Write-Output 'changed'
  - id: quiet-restart
    description: Not marked gated, yet a step restarts a service
    host_ids: ['*']
    requires_permission: false
    steps:
      - id: restart
        desc: Restart a service
        run: Restart-Service W3SVC
  - id: read-only
    description: Nothing to gate
    host_ids: ['*']
    requires_permission: false
    steps:
      - id: look
        desc: Look
        run: Write-Output 'ok'
"""


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def gatekeeper(clock: Clock) -> LocalGatekeeper:
    return LocalGatekeeper(approval_timeout_s=600, clock=clock)


@pytest.fixture
def session(config_files: Path, gatekeeper: LocalGatekeeper) -> FakeSession:
    (config_files / "operations.yaml").write_text(textwrap.dedent(OPERATIONS), encoding="utf-8")
    fake = FakeSession(
        load_inventory(config_files / "inventory.yaml"),
        load_operations(config_files / "operations.yaml"),
        "win01",
    )
    fake.gatekeeper = gatekeeper
    fake.agent_attached = False
    return fake


def request(gk: LocalGatekeeper, commands: str = "  [only] Write-Output 'changed'") -> Any:
    return gk.request_approval("spiffe://x/agent/a", "gated-op", commands, "SES-1")


def approve(gk: LocalGatekeeper, request_id: str) -> bool:
    return gk.resolve_approval(request_id, "allow", by="user:op")


def held_id(exc: pytest.ExceptionInfo[PermissionRequired], gk: LocalGatekeeper) -> str:
    request_id = gk.pending_approvals()[0]["request_id"]
    assert request_id in str(exc.value) and ":approve" in str(exc.value)
    return request_id


class TestLocalApprovalStore:
    def test_a_first_request_is_held_and_polling_returns_the_same_one(self, gatekeeper) -> None:
        first, again = request(gatekeeper), request(gatekeeper)
        assert first.status == "pending"
        assert again == first

    def test_an_approval_authorizes_exactly_one_run(self, gatekeeper) -> None:
        ticket = request(gatekeeper)
        assert approve(gatekeeper, ticket.request_id)
        assert request(gatekeeper).status == "approved"
        fresh = request(gatekeeper)
        assert fresh.status == "pending" and fresh.request_id != ticket.request_id

    def test_a_denial_is_reported_once_and_consumed(self, gatekeeper) -> None:
        ticket = request(gatekeeper)
        assert gatekeeper.resolve_approval(ticket.request_id, "deny", by="user:op")
        assert request(gatekeeper).status == "denied"
        assert request(gatekeeper).status == "pending"

    def test_an_approval_is_bound_to_the_commands_it_showed(self, gatekeeper) -> None:
        ticket = request(gatekeeper, "  [only] Write-Output 'changed'")
        approve(gatekeeper, ticket.request_id)
        other = request(gatekeeper, "  [only] Remove-Item C:\\data")
        assert other.status == "pending" and other.request_id != ticket.request_id

    def test_an_unanswered_request_lapses_into_a_denial(self, gatekeeper, clock) -> None:
        ticket = request(gatekeeper)
        clock.now = 601
        assert gatekeeper.pending_approvals() == []
        assert not approve(gatekeeper, ticket.request_id), "a lapsed request stays lapsed"
        assert request(gatekeeper).status == "timed_out"

    def test_pending_rows_carry_what_the_approver_must_read(self, gatekeeper, clock) -> None:
        ticket = request(gatekeeper)
        clock.now = 100
        (row,) = gatekeeper.pending_approvals()
        assert row["request_id"] == ticket.request_id
        assert row["tool"] == "gated-op" and "Write-Output 'changed'" in row["detail"]
        assert row["remaining_s"] == 500

    def test_filing_a_request_announces_it_once(self, clock) -> None:
        seen: list[dict[str, Any]] = []
        gk = LocalGatekeeper(approval_timeout_s=600, clock=clock, on_request=seen.append)
        request(gk), request(gk)
        assert [row["tool"] for row in seen] == ["gated-op"]

    def test_an_unknown_request_cannot_be_resolved(self, gatekeeper) -> None:
        assert not approve(gatekeeper, "nope")


class TestHumanPathIsUnchanged:
    def test_confirm_from_a_human_runs_the_gated_operation(self, session) -> None:
        outcome = Engine(session).run_operation("gated-op", confirmed=True)
        assert outcome.ok and len(session.commands) == 1

    def test_without_confirm_it_is_refused_as_before(self, session) -> None:
        with pytest.raises(PermissionRequired, match="re-run with confirmation"):
            Engine(session).run_operation("gated-op")


class TestAgentRequestsAreHeld:
    def test_confirm_from_an_agent_does_not_run_it(self, session, gatekeeper) -> None:
        with pytest.raises(PermissionRequired) as exc:
            Engine(session).run_operation("gated-op", confirmed=True, agent_caller=True)
        held_id(exc, gatekeeper)
        assert session.commands == []

    def test_it_runs_once_after_the_operator_approves(self, session, gatekeeper) -> None:
        engine = Engine(session)
        with pytest.raises(PermissionRequired) as exc:
            engine.run_operation("gated-op", agent_caller=True)
        approve(gatekeeper, held_id(exc, gatekeeper))

        assert engine.run_operation("gated-op", agent_caller=True).ok
        assert len(session.commands) == 1
        with pytest.raises(PermissionRequired):
            engine.run_operation("gated-op", agent_caller=True)
        assert len(session.commands) == 1, "one approval, one run"

    def test_a_denied_request_never_runs(self, session, gatekeeper) -> None:
        engine = Engine(session)
        with pytest.raises(PermissionRequired) as exc:
            engine.run_operation("gated-op", agent_caller=True)
        gatekeeper.resolve_approval(held_id(exc, gatekeeper), "deny", by="user:op")
        with pytest.raises(PermissionRequired, match="denied"):
            engine.run_operation("gated-op", agent_caller=True)
        assert session.commands == []

    def test_an_agent_attached_session_is_held_the_same_way(self, session, gatekeeper) -> None:
        session.agent_attached = True
        with pytest.raises(PermissionRequired) as exc:
            Engine(session).run_operation("gated-op", confirmed=True)
        held_id(exc, gatekeeper)

    def test_confirm_cannot_wave_a_gated_step_through_an_ungated_operation(
        self, session, gatekeeper
    ) -> None:
        """The operation is not marked gated, but its step is confirm-class: an
        agent's --confirm must not satisfy the per-step gate either."""
        with pytest.raises(PermissionRequired) as exc:
            Engine(session).run_operation("quiet-restart", confirmed=True, agent_caller=True)
        held_id(exc, gatekeeper)
        assert session.commands == []

    def test_an_ungated_read_only_operation_needs_no_approval(self, session) -> None:
        assert Engine(session).run_operation("read-only", agent_caller=True).ok

    def test_the_hold_is_audited(self, session, audit_log, gatekeeper) -> None:
        session.audit = audit_log
        with pytest.raises(PermissionRequired):
            Engine(session).run_operation("gated-op", agent_caller=True)
        (record,) = [r for r in audit_log.records if r.get("action") == "PERMISSION_REQUEST"]
        assert record["result"] == "PENDING"
        assert record["request_id"] == gatekeeper.pending_approvals()[0]["request_id"]


class TestAgentAdHocCommands:
    def test_a_confirm_class_command_is_held(self, session, gatekeeper) -> None:
        with pytest.raises(PermissionRequired) as exc:
            Engine(session).run_command("Restart-Service W3SVC", confirmed=True, agent_caller=True)
        held_id(exc, gatekeeper)
        assert session.commands == []

    def test_it_runs_after_approval(self, session, gatekeeper) -> None:
        engine = Engine(session)
        with pytest.raises(PermissionRequired) as exc:
            engine.run_command("Restart-Service W3SVC", agent_caller=True)
        approve(gatekeeper, held_id(exc, gatekeeper))
        assert engine.run_command("Restart-Service W3SVC", agent_caller=True).ok

    def test_an_allowed_command_runs_straight_away(self, session) -> None:
        assert Engine(session).run_command("hostname", agent_caller=True).ok

    def test_a_human_confirm_still_works(self, session) -> None:
        assert Engine(session).run_command("Restart-Service W3SVC", confirmed=True).ok


class TestOverTheSessionSocket:
    """The same flow as a client sees it: a real socket, the real server."""

    def test_hold_approve_run(self, session, gatekeeper, tmp_path, monkeypatch) -> None:
        from access_control.errors import AccessControlError

        from test_daemon import RunningServer

        monkeypatch.setenv("AC_DATA_DIR", str(tmp_path / "data"))
        session.expired = False  # the server's watchdog reads it
        with RunningServer(session) as (client, _):
            with pytest.raises(AccessControlError, match=":approve") as exc:
                client.call(
                    "run_operation", operation_id="gated-op", confirmed=True, agent_caller=True
                )
            (row,) = gatekeeper.pending_approvals()
            assert row["request_id"] in str(exc.value)
            assert session.commands == []

            approve(gatekeeper, row["request_id"])
            result = client.call("run_operation", operation_id="gated-op", agent_caller=True)

        assert result["ok"] and len(session.commands) == 1


class RecordingAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def emit(self, event: str, **fields: Any) -> None:
        self.events.append((event, fields))


class PromptSession:
    """The slice of Session the :approve verb touches."""

    def __init__(self, gatekeeper: Any, **flags: bool) -> None:
        self.gatekeeper = gatekeeper
        self.agent_attached = flags.get("agent_attached", False)
        self.agent_held_prompt = flags.get("agent_held_prompt", False)
        self.audit = RecordingAudit()


def make_shell(gatekeeper: Any, **flags: bool):
    out, err = io.StringIO(), io.StringIO()
    shell = OperatorShell(
        PromptSession(gatekeeper, **flags),
        Console(file=out, force_terminal=False, width=200),
        Console(file=err, force_terminal=False, width=200),
    )
    return shell, out, err


class TestApprovingAtTheConnectPrompt:
    def test_the_list_shows_the_commands_awaiting_approval(self, gatekeeper) -> None:
        ticket = request(gatekeeper)
        shell, out, _ = make_shell(gatekeeper)
        shell._meta("approve")
        text = out.getvalue()
        assert ticket.request_id in text and "Write-Output 'changed'" in text

    def test_a_human_prompt_approves_for_an_agent_attached_session(self, gatekeeper) -> None:
        """--agent-id says an agent will drive the session; the prompt is still
        the human's own terminal, and is where the approval belongs."""
        ticket = request(gatekeeper)
        shell, out, _ = make_shell(gatekeeper, agent_attached=True)
        shell._meta(f"approve {ticket.request_id}")
        assert "approved" in out.getvalue()
        assert request(gatekeeper).status == "approved"

    def test_a_prompt_held_by_an_agent_cannot_approve(self, gatekeeper) -> None:
        ticket = request(gatekeeper)
        shell, _, err = make_shell(gatekeeper, agent_attached=True, agent_held_prompt=True)
        shell._meta(f"approve {ticket.request_id}")
        assert "agent" in err.getvalue().lower()
        assert request(gatekeeper).status == "pending"

    def test_a_resolution_is_recorded_in_the_trail(self, gatekeeper) -> None:
        ticket = request(gatekeeper)
        shell, _, _ = make_shell(gatekeeper)
        shell._meta(f"deny {ticket.request_id}")
        (event, fields), = shell.session.audit.events
        assert event == "approval.resolved"
        assert fields["request_id"] == ticket.request_id and fields["decision"] == "deny"
        assert fields["resolved_by"].startswith("user:")


class TestSessionWiring:
    @pytest.fixture
    def build(self, config_files: Path, monkeypatch: pytest.MonkeyPatch):
        from access_control.daemon import build_session

        monkeypatch.setenv("AC_DATA_DIR", str(config_files.parent / "data"))

        def factory(**kwargs: Any):
            return build_session(
                "lin01",
                inventory=load_inventory(config_files / "inventory.yaml"),
                catalog=load_operations(config_files / "operations.yaml"),
                **kwargs,
            )

        return factory

    def test_a_plain_session_holds_its_own_approvals(self, build) -> None:
        session = build()
        assert isinstance(session.gatekeeper, LocalGatekeeper)
        assert not session.agent_attached and not session.agent_held_prompt

    def test_agent_id_marks_the_session_but_not_the_prompt(self, build) -> None:
        session = build(agent_id="AGT-web01")
        assert session.agent_attached and not session.agent_held_prompt

    def test_connect_inside_an_agent_harness_marks_the_prompt(
        self, build, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CLAUDECODE", "1")
        session = build()
        assert session.agent_attached and session.agent_held_prompt


class CallRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, method: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, kwargs))
        if method == "run_command":
            return ExecResult(
                node_id="win01", channel="fake", command=kwargs["command"], exit_code=0
            ).to_dict()
        return {"ok": True, "operation_id": kwargs.get("operation_id"), "host_id": "win01",
                "status": "ok", "duration_s": 0.1, "steps": []}


class TestClientsDeclareAnAgentCaller:
    @pytest.fixture
    def client(self, config_files: Path, monkeypatch: pytest.MonkeyPatch) -> CallRecorder:
        monkeypatch.setenv("AC_CONFIG_DIR", str(config_files))
        recorder = CallRecorder()
        monkeypatch.setattr(cli, "attach", lambda host: recorder)
        monkeypatch.setattr(cli, "_client_or_fail", lambda host: recorder)
        return recorder

    def test_ac_run_inside_a_harness_says_so(self, client, monkeypatch) -> None:
        monkeypatch.setenv("CLAUDECODE", "1")
        CliRunner().invoke(cli.app, ["run", "win01", "echo-op", "-p", "message=hi", "--confirm"])
        (method, kwargs), = client.calls
        assert method == "run_operation" and kwargs["agent_caller"] is True

    def test_ac_run_from_a_plain_terminal_does_not(self, client) -> None:
        CliRunner().invoke(cli.app, ["run", "win01", "echo-op", "-p", "message=hi", "--confirm"])
        (_method, kwargs), = client.calls
        assert "agent_caller" not in kwargs

    def test_ac_exec_inside_a_harness_says_so(self, client, monkeypatch) -> None:
        monkeypatch.setenv("CLAUDECODE", "1")
        CliRunner().invoke(cli.app, ["exec", "win01", "--", "hostname"])
        (method, kwargs), = client.calls
        assert method == "run_command" and kwargs["agent_caller"] is True
