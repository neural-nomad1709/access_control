"""Operation execution: templating, gating, expectations, and failure diagnosis."""

from __future__ import annotations

from pathlib import Path

import pytest

from access_control.audit import EV_BLOCKED, EV_OPERATION_END, EV_STEP_END
from access_control.engine import Engine, evaluate, tail_command
from access_control.errors import ConfigError, PermissionRequired, TemplateError
from access_control.template import placeholders, render
from access_control.transport.base import ExecResult, clamp_output
from access_control.transport.pshell import parse_exit, wrap_script


def ok(command: str, stdout: str = "", exit_code: int = 0) -> ExecResult:
    return ExecResult(
        node_id="win01", channel="fake", command=command, exit_code=exit_code, stdout=stdout
    )


class TestTemplating:
    def test_renders_placeholders(self) -> None:
        assert render("install {{pkg}} on {{host}}", {"pkg": "a.msi", "host": "h"}) == (
            "install a.msi on h"
        )

    def test_missing_variables_are_all_named_at_once(self) -> None:
        with pytest.raises(TemplateError, match="one, two"):
            render("{{one}} {{two}}", {})

    def test_a_none_value_counts_as_missing(self) -> None:
        """An empty substitution in `Remove-Item {{path}}` is how you delete the wrong thing."""
        with pytest.raises(TemplateError):
            render("Remove-Item {{path}}", {"path": None})

    def test_placeholders_are_listed_in_order_without_duplicates(self) -> None:
        assert placeholders("{{a}} {{b}} {{a}}") == ["a", "b"]

    def test_powershell_syntax_is_not_mistaken_for_a_placeholder(self) -> None:
        script = '$h = @{Name="x"}; "$($h.Name)"'
        assert placeholders(script) == []
        assert render(script, {}) == script


class TestPowerShellWrapping:
    def test_exit_sentinel_round_trips(self) -> None:
        stdout, code = parse_exit("some output\n__AC_EXIT__:1603")
        assert code == 1603
        assert stdout == "some output"

    def test_absent_sentinel_returns_none(self) -> None:
        assert parse_exit("plain output") == ("plain output", None)

    def test_last_sentinel_wins(self) -> None:
        """The nested leg produces two: the target's must win over the jump server's."""
        _, code = parse_exit("__AC_EXIT__:0\ninner output\n__AC_EXIT__:3010")
        assert code == 3010

    def test_negative_exit_codes_parse(self) -> None:
        assert parse_exit("__AC_EXIT__:-1")[1] == -1

    def test_wrapper_preserves_the_script_body(self) -> None:
        wrapped = wrap_script("Get-Service W3SVC")
        assert "Get-Service W3SVC" in wrapped
        assert "__AC_EXIT__" in wrapped

    def test_out_string_variant_keeps_error_stream_separate(self) -> None:
        wrapped = wrap_script("Get-Item x", out_string=True)
        assert "| Out-String" in wrapped
        assert "*>&1" not in wrapped  # merging streams would bury the diagnosis


class TestOutputClamping:
    def test_short_output_is_untouched(self) -> None:
        assert clamp_output("hello", 100) == ("hello", False)

    def test_long_output_keeps_head_and_tail(self) -> None:
        text = "A" * 500 + "MIDDLE" + "Z" * 500
        clamped, truncated = clamp_output(text, 200)
        assert truncated
        assert clamped.startswith("A")
        assert clamped.endswith("Z")
        assert "characters omitted" in clamped
        assert "MIDDLE" not in clamped


class TestExpectations:
    def _step(self, catalog, op_id="echo-op", step_id="first"):
        return next(s for s in catalog.get(op_id).steps if s.id == step_id)

    def test_default_expects_exit_zero(self, catalog) -> None:
        step = self._step(catalog, "echo-op", "second")
        assert evaluate(step, ok("c", "out"))[0]
        assert not evaluate(step, ok("c", "out", exit_code=1))[0]

    def test_failure_reason_names_expected_and_actual(self, catalog) -> None:
        met, reason = evaluate(self._step(catalog, "echo-op", "second"), ok("c", "", 1603))
        assert not met
        assert "expected exit code 0" in reason and "1603" in reason

    def test_stdout_contains(self, catalog) -> None:
        step = self._step(catalog)
        assert not evaluate(step, ok("c", "nothing here"))[0]

    def test_timeout_is_reported_before_anything_else(self, catalog) -> None:
        result = ExecResult(node_id="n", channel="fake", command="c", timed_out=True)
        met, reason = evaluate(self._step(catalog, "echo-op", "second"), result)
        assert not met and "timed out" in reason

    def test_expectations_are_templated(self, catalog) -> None:
        """`stdout_contains: '{{message}}'` must match the rendered value.

        Without this an operation could only ever assert on literals, so
        "confirm the output mentions the package we installed" would be
        impossible to express.
        """
        step = self._step(catalog, "echo-op", "first")
        variables = {"message": "hello"}
        assert evaluate(step, ok("c", "hello world"), variables)[0]
        assert not evaluate(step, ok("c", "goodbye"), variables)[0]

    def test_untemplated_evaluation_still_works(self, catalog) -> None:
        step = self._step(catalog, "echo-op", "first")
        assert evaluate(step, ok("c", "literal {{message}} here"))[0]


class TestPermissionGate:
    def test_gated_operation_refuses_without_confirmation(self, make_session) -> None:
        engine = Engine(make_session("win01"))
        with pytest.raises(PermissionRequired) as exc:
            engine.run_operation("needs-approval")
        # The refusal must show the operator exactly what would run.
        assert "Restart-Service W3SVC" in str(exc.value)

    def test_gated_operation_runs_once_confirmed(self, make_session) -> None:
        session = make_session("win01")
        outcome = Engine(session).run_operation("needs-approval", confirmed=True)
        assert outcome.ok
        assert any("Restart-Service" in c for c in session.commands)

    def test_ungated_operation_runs_directly(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hello"))
        assert Engine(session).run_operation("echo-op", {"message": "hello"}).ok

    def test_session_allow_list_is_enforced(self, make_session) -> None:
        session = make_session("win01", allowed_operations=("echo-op",))
        with pytest.raises(PermissionRequired, match="ac connect"):
            Engine(session).run_operation("needs-approval", confirmed=True)

    def test_operation_not_permitted_on_this_host(self, make_session) -> None:
        engine = Engine(make_session("lin01"))
        with pytest.raises(ConfigError, match="not permitted on host 'lin01'"):
            engine.run_operation("needs-approval", confirmed=True)

    def test_blocked_command_stops_the_step_even_when_confirmed(self, make_session) -> None:
        session = make_session("win01")
        engine = Engine(session)
        with pytest.raises(Exception):
            engine.run_command("Format-Volume -DriveLetter D", confirmed=True)
        assert session.commands == []


class TestDryRun:
    def test_dry_run_sends_nothing(self, make_session) -> None:
        session = make_session("win01")
        outcome = Engine(session).run_operation("echo-op", {"message": "hi"}, dry_run=True)
        assert outcome.status == "dry-run" and outcome.ok
        assert session.commands == []

    def test_dry_run_reports_gating_instead_of_blocking(self, make_session) -> None:
        """A dry run exists to show what *would* happen, including what needs approval."""
        outcome = Engine(make_session("win01")).run_operation("needs-approval", dry_run=True)
        assert outcome.ok
        step = outcome.steps[0]
        assert step.status == "dry-run"
        assert "would require" in step.expectation_reason

    def test_preview_renders_without_a_connection(self, make_session) -> None:
        preview = Engine(make_session("win01")).preview("echo-op", {"message": "hello"})
        assert preview["steps"][0]["command"].strip() == "Write-Output 'hello'"
        assert preview["requires_permission"] is False

    def test_preview_reports_missing_variables(self, make_session) -> None:
        with pytest.raises(ConfigError, match="requires parameter"):
            Engine(make_session("win01")).preview("echo-op")


class TestFailureDiagnosis:
    def _failing(self, make_session, log_text="MSI error 1603 near line 40"):
        def responder(command: str) -> ExecResult:
            if "exit 1603" in command:
                return ok(command, "about to fail", exit_code=1603)
            return ok(command, log_text)

        return make_session("win01", responder=responder)

    def test_operation_stops_at_the_first_failure(self, make_session) -> None:
        session = self._failing(make_session)
        outcome = Engine(session).run_operation("failing-op")
        assert outcome.status == "failed"
        assert outcome.stopped_at == "boom"
        assert [s.step_id for s in outcome.steps] == ["boom"]
        assert not any("unreachable" in c for c in session.commands)

    def test_failure_collects_the_nominated_logs(self, make_session) -> None:
        outcome = Engine(self._failing(make_session)).run_operation("failing-op")
        collected = outcome.steps[0].collected
        assert collected, "on_failure.collect should have produced material"
        assert "MSI error 1603" in collected[0]["content"]

    def test_hint_matches_the_exit_code(self, make_session) -> None:
        outcome = Engine(self._failing(make_session)).run_operation("failing-op")
        assert outcome.steps[0].hint == "Generic MSI failure -- read the collected log"

    def test_catch_all_hint_is_used_for_other_codes(self, make_session) -> None:
        def responder(command: str) -> ExecResult:
            return ok(command, "", exit_code=5) if "exit 1603" in command else ok(command, "log")

        outcome = Engine(make_session("win01", responder=responder)).run_operation("failing-op")
        assert outcome.steps[0].hint == "Something else went wrong"

    def test_result_tells_the_agent_what_to_do_next(self, make_session) -> None:
        data = Engine(self._failing(make_session)).run_operation("failing-op").to_dict()
        assert "collected_logs" in data["steps"][0]
        assert "hint" in data["steps"][0]
        assert "run_command" in data["next_action"]

    def test_a_broken_collector_does_not_mask_the_real_failure(self, make_session) -> None:
        def responder(command: str) -> ExecResult:
            if "exit 1603" in command:
                return ok(command, "", exit_code=1603)
            raise RuntimeError("the collector itself blew up")

        outcome = Engine(make_session("win01", responder=responder)).run_operation("failing-op")
        assert outcome.steps[0].status == "failed"
        assert "could not collect" in outcome.steps[0].collected[0]["error"]


class TestOperationReport:
    """PLAN.md: an end-to-end summary after each operation, to share with the user."""

    def test_success_report_states_the_verdict_plainly(self, make_session, audit_log) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"), audit=audit_log)
        outcome = Engine(session).run_operation("echo-op", {"message": "hi"})
        report = outcome.report_markdown()
        assert "SUCCEEDED" in report
        assert "win01" in report
        assert "| 1 | first" in report and "| 2 | second" in report
        assert "No action required" in report

    def test_failure_report_carries_the_evidence(self, make_session, audit_log) -> None:
        def responder(command: str) -> ExecResult:
            if "exit 1603" in command:
                return ok(command, "about to fail", exit_code=1603)
            return ok(command, "MSI error 1603 near line 40")

        session = make_session("win01", responder=responder, audit=audit_log)
        report = Engine(session).run_operation("failing-op").report_markdown()

        assert "FAILED" in report
        assert "Why it stopped: `boom`" in report
        assert "expected exit code 0" in report
        assert "MSI error 1603" in report, "the collected log belongs in the report"
        assert "Generic MSI failure" in report, "so does the hint"
        # And the exact command to resume from, so the reader can act.
        assert "--start-at boom" in report

    def test_report_is_written_to_disk_next_to_the_audit_trail(
        self, make_session, audit_log
    ) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"), audit=audit_log)
        outcome = Engine(session).run_operation("echo-op", {"message": "hi"})
        assert outcome.summary_file is not None
        path = Path(outcome.summary_file)
        assert path.exists()
        assert "echo-op" in path.name
        assert "SUCCEEDED" in path.read_text(encoding="utf-8")

    def test_report_travels_with_the_result(self, make_session, audit_log) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"), audit=audit_log)
        data = Engine(session).run_operation("echo-op", {"message": "hi"}).to_dict()
        assert "summary" in data and "SUCCEEDED" in data["summary"]
        assert "summary_file" in data

    def test_reports_do_not_overwrite_each_other(self, make_session, audit_log) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"), audit=audit_log)
        engine = Engine(session)
        first = engine.run_operation("echo-op", {"message": "hi"})
        second = engine.run_operation("echo-op", {"message": "hi"})
        assert first.summary_file != second.summary_file

    def test_report_contains_no_secret(self, make_session, audit_log) -> None:
        from access_control import redact

        redact.register("very-secret-password")
        try:
            session = make_session(
                "win01",
                responder=lambda c: ok(c, "logged in with very-secret-password"),
                audit=audit_log,
            )
            report = Engine(session).run_operation("echo-op", {"message": "hi"}).report_markdown()
            assert "very-secret-password" not in report
        finally:
            redact.clear()


class TestStepSelection:
    def test_start_at_resumes_from_a_step(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"))
        outcome = Engine(session).run_operation(
            "echo-op", {"message": "hi"}, start_at="second"
        )
        assert [s.step_id for s in outcome.steps] == ["second"]

    def test_only_steps_runs_a_subset(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"))
        outcome = Engine(session).run_operation(
            "echo-op", {"message": "hi"}, only_steps=["first"]
        )
        assert [s.step_id for s in outcome.steps] == ["first"]

    def test_unknown_step_lists_the_real_ones(self, make_session) -> None:
        with pytest.raises(ConfigError, match="first, second"):
            Engine(make_session("win01")).run_operation(
                "echo-op", {"message": "x"}, start_at="nope"
            )


class TestAuditTrail:
    def test_every_step_is_recorded(self, make_session, audit_log) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"), audit=audit_log)
        Engine(session).run_operation("echo-op", {"message": "hi"})

        steps = audit_log.by_event(EV_STEP_END)
        assert [s["step_id"] for s in steps] == ["first", "second"]
        # Canonical identity spellings, so the trail drops into a SIEM unchanged.
        assert all(s["sessionId"] == session.session_id for s in steps)
        assert all(s["agentId"] == "pytest" for s in steps)
        assert all(s["host_id"] == "win01" for s in steps)
        assert all(s["timestamp"] for s in steps)

    def test_operation_end_records_the_outcome(self, make_session, audit_log) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"), audit=audit_log)
        Engine(session).run_operation("echo-op", {"message": "hi"})
        end = audit_log.by_event(EV_OPERATION_END)[0]
        assert end["status"] == "ok" and end["operation_id"] == "echo-op"

    def test_blocked_commands_are_recorded(self, make_session, audit_log) -> None:
        session = make_session("win01", audit=audit_log)
        engine = Engine(session)
        op = session.catalog.get("needs-approval")
        engine.run_step(op, op.steps[0], {}, confirmed=False)
        assert audit_log.by_event(EV_BLOCKED)

    def test_trail_survives_on_disk(self, make_session, audit_log) -> None:
        session = make_session("win01", responder=lambda c: ok(c, "hi"), audit=audit_log)
        Engine(session).run_operation("echo-op", {"message": "hi"})
        audit_log.close()
        assert audit_log.path.exists()
        assert audit_log.path.with_suffix(".md").exists()
        assert "echo-op" in audit_log.path.with_suffix(".md").read_text(encoding="utf-8")


class TestActionLogging:
    """Canonical action records and the execution timeline."""

    def test_action_record_matches_the_declared_shape(self, audit_log) -> None:
        record = audit_log.action(
            "SSH_CONNECT", source="JumpServer01", target="linux-app01", result="SUCCESS"
        )
        for key in ("timestamp", "agentId", "sessionId", "action", "source", "target", "result"):
            assert key in record, key
        assert record["action"] == "SSH_CONNECT"
        assert record["source"] == "JumpServer01"
        assert record["target"] == "linux-app01"
        assert record["result"] == "SUCCESS"

    def test_source_defaults_to_local(self, audit_log) -> None:
        assert audit_log.action("SSH_CONNECT", target="bastion1")["source"] == "local"

    def test_timeline_lists_actions_in_order(self, audit_log) -> None:
        audit_log.action("SSH_CONNECT", source="local", target="bastion1")
        audit_log.action("SSH_CONNECT", source="bastion1", target="app01")
        audit_log.emit("step.end", step_id="ignored")  # not an action
        audit_log.action("COMMAND_EXECUTE", source="local", target="app01", detail="df -h")

        timeline = audit_log.timeline()
        assert [e["action"] for e in timeline] == [
            "SSH_CONNECT",
            "SSH_CONNECT",
            "COMMAND_EXECUTE",
        ]
        assert timeline[-1]["detail"] == "df -h"

    def test_rendered_timeline_is_readable(self, audit_log) -> None:
        audit_log.action("SSH_CONNECT", source="local", target="bastion1", duration_s=1.2)
        audit_log.action("COMMAND_EXECUTE", source="local", target="app01", result="FAILURE")
        rendered = audit_log.render_timeline()
        assert "SSH_CONNECT" in rendered
        assert "local -> bastion1" in rendered
        assert "(1.2s)" in rendered
        assert "[FAILURE]" in rendered

    def test_timeline_is_included_in_the_markdown_summary(self, audit_log) -> None:
        audit_log.action("SSH_CONNECT", source="local", target="bastion1")
        path = audit_log.write_markdown_summary()
        assert "Execution timeline" in path.read_text(encoding="utf-8")

    def test_secrets_never_reach_an_action_record(self, audit_log) -> None:
        from access_control import redact

        redact.register("hunter2-the-password")
        try:
            audit_log.action(
                "AUTHENTICATE", target="bastion1", detail="tried hunter2-the-password"
            )
            assert "hunter2-the-password" not in audit_log.path.read_text(encoding="utf-8")
        finally:
            redact.clear()

    def test_disabled_logging_writes_nothing_to_disk(self, tmp_path) -> None:
        from access_control.audit import AuditLog

        log = AuditLog(
            session_id="SES-000001",
            agent_id="AGT-TEST",
            directory=tmp_path,
            trace_id="trace-1",
            enabled=False,
        )
        log.action("SSH_CONNECT", target="b1")
        assert not log.path.exists()
        # ...but the in-memory trail still backs `ac status`.
        assert len(log.records) == 1

    def test_trace_id_names_the_file(self, tmp_path) -> None:
        from access_control.audit import AuditLog

        log = AuditLog(
            session_id="SES-000042",
            agent_id="AGT-TEST",
            directory=tmp_path,
            trace_id="20260812T120000Z-000042",
        )
        assert log.path.name == "20260812T120000Z-000042.jsonl"


class TestLogTailing:
    def test_windows_glob_resolves_to_the_newest_match(self) -> None:
        command = tail_command("C:\\Windows\\Temp\\*.log", 50, windows=True)
        assert "Sort-Object LastWriteTime -Descending" in command
        assert "-Tail 50" in command

    def test_posix_tail_is_tolerant_of_a_missing_file(self) -> None:
        command = tail_command("/var/log/messages", 20, windows=False)
        assert command.startswith("tail -n 20")
        assert "no such file" in command
