"""Task briefs and preflight validation.

The brief is the instruction document an operator writes; validation exists so a
badly-formed instruction fails while it is still cheap to fix, rather than in the
middle of a change window.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from access_control.brief import (
    BriefRules,
    TaskBrief,
    load_brief,
    validate_brief,
)
from access_control.errors import ConfigError
from access_control.preflight import (
    FATAL,
    WARNING,
    CheckResult,
    PreflightReport,
    check_chain_intact,
    check_disk_space,
    check_identity,
    check_round_trip,
    check_services_running,
    run_preflight,
    _names_match,
)
from access_control.transport.base import ExecResult

VALID = """
brief:
  id: TB-001
  title: Install the thing
  host: win01
  requested_by: tester
  change_ref: CHG1
preflight:
  expect_hostname: WIN01
operations:
  - operation: echo-op
    params: {message: hello}
success_criteria:
  - It worked
"""


def write(tmp_path: Path, body: str, name: str = "brief.yaml") -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------


class TestBriefParsing:
    def test_loads_a_valid_brief(self, tmp_path: Path) -> None:
        brief = load_brief(write(tmp_path, VALID))
        assert brief.id == "TB-001"
        assert brief.host == "win01"
        assert brief.operation_ids == ("echo-op",)
        assert brief.operations[0].params == {"message": "hello"}

    def test_a_bare_string_is_an_operation(self, tmp_path: Path) -> None:
        brief = load_brief(
            write(
                tmp_path,
                """
                brief: {id: T, title: t, host: win01}
                operations: [echo-op]
                """,
            )
        )
        assert brief.operation_ids == ("echo-op",)
        assert brief.operations[0].on_failure == "stop"

    def test_missing_brief_block_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="must start with a 'brief:' block"):
            load_brief(write(tmp_path, "operations: [echo-op]"))

    @pytest.mark.parametrize("field", ["id", "title", "host"])
    def test_required_brief_fields(self, tmp_path: Path, field: str) -> None:
        body = {"id": "T", "title": "t", "host": "win01"}
        body.pop(field)
        rendered = "\n".join(f"  {k}: {v}" for k, v in body.items())
        with pytest.raises(ConfigError, match=f"brief.{field}: required"):
            load_brief(write(tmp_path, f"brief:\n{rendered}\noperations: [echo-op]"))

    def test_a_brief_with_no_operations_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="a brief with nothing to do"):
            load_brief(write(tmp_path, "brief: {id: T, title: t, host: win01}"))

    def test_unknown_on_failure_mode_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="on_failure"):
            load_brief(
                write(
                    tmp_path,
                    """
                    brief: {id: T, title: t, host: win01}
                    operations:
                      - {operation: echo-op, on_failure: panic}
                    """,
                )
            )

    def test_a_misspelled_rule_is_rejected_not_ignored(self, tmp_path: Path) -> None:
        """A silently-ignored rule is worse than a rejected one."""
        with pytest.raises(ConfigError, match="unknown rule"):
            load_brief(
                write(
                    tmp_path,
                    """
                    brief: {id: T, title: t, host: win01}
                    operations: [echo-op]
                    rules: {reboots_allowed: true}
                    """,
                )
            )

    def test_missing_file_is_reported_clearly(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="task brief not found"):
            load_brief(tmp_path / "absent.yaml")

    def test_rules_default_to_the_cautious_setting(self) -> None:
        rules = BriefRules()
        assert rules.confirm_destructive is True
        assert rules.stop_on_first_failure is True
        assert rules.reboot_allowed is False
        assert rules.allow_unlisted_operations is False

    def test_render_shows_what_an_operator_is_approving(self, tmp_path: Path) -> None:
        rendered = load_brief(write(tmp_path, VALID)).render()
        assert "TB-001" in rendered
        assert "win01" in rendered
        assert "echo-op" in rendered
        assert "message=hello" in rendered
        assert "on failure: stop" in rendered
        assert "It worked" in rendered


# --------------------------------------------------------------------------
# Validation against inventory and catalogue
# --------------------------------------------------------------------------


class TestBriefValidation:
    def test_a_valid_brief_passes(self, tmp_path: Path, inventory, catalog) -> None:
        brief = load_brief(write(tmp_path, VALID))
        assert validate_brief(brief, inventory, catalog) == []

    def test_unknown_host_is_rejected(self, tmp_path: Path, inventory, catalog) -> None:
        brief = load_brief(
            write(tmp_path, VALID.replace("host: win01", "host: nowhere"))
        )
        with pytest.raises(ConfigError, match="unknown host 'nowhere'"):
            validate_brief(brief, inventory, catalog)

    def test_unknown_operation_is_rejected(self, tmp_path: Path, inventory, catalog) -> None:
        brief = load_brief(
            write(tmp_path, VALID.replace("operation: echo-op", "operation: no-such-op"))
        )
        with pytest.raises(ConfigError, match="unknown operation"):
            validate_brief(brief, inventory, catalog)

    def test_operation_not_permitted_on_that_host_is_rejected(
        self, tmp_path: Path, inventory, catalog
    ) -> None:
        """`needs-approval` is bound to win01 only; lin01 must be refused."""
        brief = load_brief(
            write(
                tmp_path,
                """
                brief: {id: T, title: t, host: lin01}
                operations: [needs-approval]
                """,
            )
        )
        with pytest.raises(ConfigError, match="not permitted on host 'lin01'"):
            validate_brief(brief, inventory, catalog)

    def test_undeclared_parameter_is_rejected(self, tmp_path: Path, inventory, catalog) -> None:
        brief = load_brief(
            write(
                tmp_path,
                """
                brief: {id: T, title: t, host: win01}
                operations:
                  - {operation: echo-op, params: {mesage: typo}}
                """,
            )
        )
        with pytest.raises(ConfigError, match="not declared by the operation"):
            validate_brief(brief, inventory, catalog)

    def test_missing_required_parameter_is_rejected(
        self, tmp_path: Path, inventory, catalog
    ) -> None:
        brief = load_brief(
            write(
                tmp_path,
                """
                brief: {id: T, title: t, host: win01}
                operations: [echo-op]
                """,
            )
        )
        with pytest.raises(ConfigError, match="missing required parameter"):
            validate_brief(brief, inventory, catalog)

    def test_unknown_start_at_is_rejected(self, tmp_path: Path, inventory, catalog) -> None:
        brief = load_brief(
            write(
                tmp_path,
                """
                brief: {id: T, title: t, host: win01}
                operations:
                  - {operation: echo-op, params: {message: hi}, start_at: nope}
                """,
            )
        )
        with pytest.raises(ConfigError, match="not a step of that operation"):
            validate_brief(brief, inventory, catalog)

    def test_rollback_mode_without_a_rollback_block_is_rejected(
        self, tmp_path: Path, inventory, catalog
    ) -> None:
        brief = load_brief(
            write(
                tmp_path,
                """
                brief: {id: T, title: t, host: win01}
                operations:
                  - {operation: echo-op, params: {message: hi}, on_failure: rollback}
                """,
            )
        )
        with pytest.raises(ConfigError, match="no 'rollback:' block"):
            validate_brief(brief, inventory, catalog)

    def test_missing_expect_hostname_warns(self, tmp_path: Path, inventory, catalog) -> None:
        """The check that guards against a forward pointing at the wrong server."""
        brief = load_brief(
            write(
                tmp_path,
                """
                brief: {id: T, title: t, host: win01}
                operations:
                  - {operation: echo-op, params: {message: hi}}
                success_criteria: [done]
                """,
            )
        )
        warnings = validate_brief(brief, inventory, catalog)
        assert any("expect_hostname" in w and "wrong server" in w for w in warnings)

    def test_missing_success_criteria_warns(self, tmp_path: Path, inventory, catalog) -> None:
        brief = load_brief(write(tmp_path, VALID.replace("success_criteria:\n  - It worked", "")))
        warnings = validate_brief(brief, inventory, catalog)
        assert any("success_criteria" in w for w in warnings)

    def test_missing_change_ref_warns(self, tmp_path: Path, inventory, catalog) -> None:
        brief = load_brief(write(tmp_path, VALID.replace("  change_ref: CHG1", "")))
        warnings = validate_brief(brief, inventory, catalog)
        assert any("change_ref" in w for w in warnings)


# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------


def ok_result(command: str, stdout: str = "", exit_code: int = 0) -> ExecResult:
    return ExecResult(
        node_id="win01", channel="fake", command=command, exit_code=exit_code, stdout=stdout
    )


class TestIdentityMatching:
    @pytest.mark.parametrize(
        "reported,expected",
        [
            ("WIN01", "win01"),
            ("win01", "WIN01"),
            ("win-target02.corp.net", "WIN-TARGET02"),
            ("WIN-TARGET02", "win-target02.corp.net"),
            ("aix-target01", "aix-target01"),
        ],
    )
    def test_names_that_should_match(self, reported: str, expected: str) -> None:
        assert _names_match(reported, expected)

    @pytest.mark.parametrize(
        "reported,expected",
        [("win01", "win02"), ("prod-db01", "qa-db01"), ("aix-target01", "aix-target02")],
    )
    def test_names_that_must_not_match(self, reported: str, expected: str) -> None:
        assert not _names_match(reported, expected)


class TestPreflightChecks:
    def test_identity_confirms_the_right_host(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok_result(c, "WIN01"))
        check = check_identity(session, "win01")
        assert check.passed and "confirmed" in check.detail

    def test_identity_catches_the_wrong_host(self, make_session) -> None:
        """The failure this check exists for: a forward pointing somewhere else.

        Commands would succeed. On the wrong machine. Nothing downstream notices.
        """
        session = make_session("win01", responder=lambda c: ok_result(c, "SOME-OTHER-BOX"))
        check = check_identity(session, "win01")
        assert not check.passed
        assert check.severity == FATAL
        assert "WRONG HOST" in check.detail
        assert "stale or reused local port forward" in check.remedy

    def test_identity_without_an_expectation_only_warns(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok_result(c, "WIN01"))
        check = check_identity(session, None)
        assert check.passed and check.severity == WARNING
        assert "expect_hostname" in check.detail

    def test_identity_fails_when_the_host_reports_nothing(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok_result(c, ""))
        assert not check_identity(session, "win01").passed

    def test_round_trip_detects_a_dead_target(self, make_session) -> None:
        def responder(command: str) -> ExecResult:
            return ExecResult(node_id="win01", channel="fake", command=command, timed_out=True)

        check = check_round_trip(make_session("win01", responder=responder))
        assert not check.passed and "ac connect" in check.remedy

    def test_disk_space_passes_when_there_is_room(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok_result(c, "FREE_GB=12.50"))
        check = check_disk_space(session, 5)
        assert check.passed and "12.50" in check.detail

    def test_disk_space_fails_when_short(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok_result(c, "FREE_GB=1.20"))
        check = check_disk_space(session, 5)
        assert not check.passed and "need 5" in check.detail

    def test_posix_df_uses_the_portable_output_format(self, make_session) -> None:
        """Found on real AIX: `df -k` puts Free in column 3, not 4.

        Without `-P` the check read "96%" as the free space and reported 0.00 GB
        on a filesystem with gigabytes available.
        """
        session = make_session("lin01", responder=lambda c: ok_result(c, "FREE_GB=4.08"))
        check_disk_space(session, 1)
        assert any("df -Pk" in c for c in session.commands)

    def test_services_check_names_the_ones_that_are_down(self, make_session) -> None:
        session = make_session(
            "win01", responder=lambda c: ok_result(c, "Winmgmt=Running\nMyApp=Stopped")
        )
        check = check_services_running(session, ["Winmgmt", "MyApp"])
        assert not check.passed and "MyApp" in check.detail

    def test_chain_intact_reports_hop_names(self, make_session) -> None:
        session = make_session("win01")
        session.ssh_hops = []
        assert check_chain_intact(session).passed


class TestPreflightOrdering:
    def test_identity_runs_before_state_checks(self, make_session) -> None:
        """No point measuring disk on a machine that turns out to be the wrong one."""
        session = make_session("win01", responder=lambda c: ok_result(c, "WRONG-BOX"))
        report = run_preflight(
            session, {"expect_hostname": "win01", "require_free_disk_gb": 5}
        )
        assert not report.ok
        assert [c.name for c in report.checks][-1] == "target.identity"
        assert not any(c.name == "disk.space" for c in report.checks)

    def test_all_checks_run_when_identity_holds(self, make_session) -> None:
        def responder(command: str) -> ExecResult:
            if "COMPUTERNAME" in command:
                return ok_result(command, "WIN01")
            if "PSDrive" in command:
                return ok_result(command, "FREE_GB=20.00")
            return ok_result(command, "ok")

        report = run_preflight(
            make_session("win01", responder=responder),
            {"expect_hostname": "win01", "require_free_disk_gb": 5},
        )
        names = [c.name for c in report.checks]
        assert names[:4] == [
            "session.live",
            "chain.intact",
            "target.responds",
            "target.identity",
        ]
        assert "disk.space" in names
        assert report.ok

    def test_a_custom_check_that_changes_state_is_refused(self, make_session) -> None:
        """Preflight verifies state; it does not create it."""
        session = make_session("win01", responder=lambda c: ok_result(c, "WIN01"))
        report = run_preflight(
            session,
            {
                "expect_hostname": "win01",
                "checks": [{"name": "bad", "run": "Remove-Item C:\\temp\\x"}],
            },
        )
        refused = next(c for c in report.checks if c.name == "custom.bad")
        assert not refused.passed
        assert "must be read-only" in refused.detail

    def test_report_renders_blockers_with_remedies(self, make_session) -> None:
        session = make_session("win01", responder=lambda c: ok_result(c, "WRONG"))
        rendered = run_preflight(session, {"expect_hostname": "win01"}).render()
        assert "FAIL" in rendered
        assert "PREFLIGHT FAILED" in rendered
        assert "no work was started" in rendered


class TestReportShape:
    def test_warnings_do_not_block(self) -> None:
        report = PreflightReport(
            host_id="win01",
            checks=[CheckResult("a", True, "fine"), CheckResult("b", False, "meh", WARNING)],
        )
        assert report.ok
        assert [c.name for c in report.warnings] == ["b"]

    def test_a_fatal_failure_blocks(self) -> None:
        report = PreflightReport(
            host_id="win01", checks=[CheckResult("a", False, "broken", FATAL)]
        )
        assert not report.ok
        assert [c.name for c in report.blockers] == ["a"]
