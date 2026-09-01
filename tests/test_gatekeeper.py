"""The Gatekeeper seam — governance as an optional plug-in, deny nothing by default.

`Gatekeeper` is the small Protocol through which an external governance plane
(AgentLighthouse) can authorize calls, hold approvals, scan output, and mirror
the audit trail into a signed ledger. `NullGatekeeper` is the default and the
contract: with it, behaviour is exactly today's — zero new dependencies, every
decision allowed, output untouched, receipts dropped.

The receipt path rides `AuditLog`: an optional sink receives every canonical
action record (post-redaction, so no secret can reach an external ledger). A
sink failure propagates — evidence is synchronous or it is not evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from access_control.audit import AuditLog
from access_control.engine import Engine
from access_control.gatekeeper import (
    ApprovalTicket,
    GateDecision,
    Gatekeeper,
    NullGatekeeper,
    ScanVerdict,
)


class RecordingGatekeeper:
    """A Gatekeeper that remembers every receipt it was handed."""

    def __init__(self) -> None:
        self.receipts: list[dict[str, Any]] = []

    def authorize(self, actor: str, tool: str, args: dict[str, Any],
                  session: str) -> GateDecision:
        return GateDecision(allowed=True)

    def request_approval(self, actor: str, tool: str, rendered_commands: str,
                         session: str) -> ApprovalTicket:
        return ApprovalTicket(request_id="t", status="approved")

    def scan_output(self, text: str, actor: str, session: str) -> ScanVerdict:
        return ScanVerdict(text=text)

    def receipt(self, **fields: Any) -> None:
        self.receipts.append(fields)


class TestNullGatekeeper:
    def test_satisfies_the_protocol(self) -> None:
        assert isinstance(NullGatekeeper(), Gatekeeper)
        assert isinstance(RecordingGatekeeper(), Gatekeeper)

    def test_is_todays_behaviour(self) -> None:
        gk = NullGatekeeper()
        assert gk.authorize("a", "t", {}, "s").allowed
        # never "approved": nothing exists to grant one, so the engine falls
        # back to the confirm gate — a plain install must not auto-approve
        ticket = gk.request_approval("a", "t", "cmd", "s")
        assert ticket.status == "not_governed"
        verdict = gk.scan_output("raw output", "a", "s")
        assert verdict.text == "raw output"
        assert not verdict.tainted
        assert gk.receipt(action="SSH_CONNECT") is None


class TestEngineSeam:
    def test_engine_still_accepts_a_bare_session(self) -> None:
        session = _FakeSession()
        engine = Engine(session)
        assert isinstance(engine.gatekeeper, NullGatekeeper)

    def test_engine_accepts_a_gatekeeper(self) -> None:
        session = _FakeSession()
        gk = RecordingGatekeeper()
        engine = Engine(session, gatekeeper=gk)
        assert engine.gatekeeper is gk


class _FakeSession:
    audit = None


class TestAuditReceiptSink:
    def _log(self, tmp_path: Path, sink) -> AuditLog:
        return AuditLog(
            session_id="SES-test", agent_id="AGT-test", host_id="win01",
            directory=tmp_path / "logs", sink=sink,
        )

    def test_every_canonical_action_reaches_the_sink(self, tmp_path: Path) -> None:
        gk = RecordingGatekeeper()
        log = self._log(tmp_path, gk.receipt)
        log.action("SSH_CONNECT", source="bastion1", target="lin01")
        log.action("COMMAND_EXECUTE", target="lin01", result="SUCCESS")
        assert [r["action"] for r in gk.receipts] == ["SSH_CONNECT", "COMMAND_EXECUTE"]
        assert gk.receipts[0]["sessionId"] == "SES-test"

    def test_the_sink_sees_redacted_records_only(self, tmp_path: Path) -> None:
        from access_control import redact

        gk = RecordingGatekeeper()
        log = self._log(tmp_path, gk.receipt)
        redact.register("hunter2-super-secret")
        try:
            log.action("COMMAND_EXECUTE", target="lin01",
                       detail="password is hunter2-super-secret")
        finally:
            redact.unregister("hunter2-super-secret")
        assert "hunter2-super-secret" not in str(gk.receipts)

    def test_no_sink_means_todays_audit_log_exactly(self, tmp_path: Path) -> None:
        log = AuditLog(session_id="SES-test", agent_id="AGT-test",
                       directory=tmp_path / "logs")
        record = log.action("SESSION_START")
        assert record["action"] == "SESSION_START"

    def test_a_failing_sink_propagates(self, tmp_path: Path) -> None:
        def broken(**fields: Any) -> None:
            raise RuntimeError("ledger unavailable")

        log = self._log(tmp_path, broken)
        with pytest.raises(RuntimeError, match="ledger unavailable"):
            log.action("SESSION_START")


class TestBuildSessionWiring:
    def _session(self, config_files: Path, monkeypatch: pytest.MonkeyPatch,
                 gk: RecordingGatekeeper):
        from access_control.config import load_inventory, load_operations
        from access_control.daemon import build_session

        monkeypatch.setenv("AC_DATA_DIR", str(config_files.parent / "data"))
        inventory = load_inventory(config_files / "inventory.yaml")
        catalog = load_operations(config_files / "operations.yaml")
        return build_session("lin01", inventory=inventory, catalog=catalog,
                             gatekeeper=gk)

    def test_build_session_attaches_the_gatekeepers_receipt_sink(
        self, config_files: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        gk = RecordingGatekeeper()
        session = self._session(config_files, monkeypatch, gk)
        session.audit.action("ROUTE_RESOLVE", target="lin01")
        assert [r["action"] for r in gk.receipts] == ["ROUTE_RESOLVE"]

    def test_the_session_owns_the_gatekeeper_and_the_engine_inherits_it(
        self, config_files: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One gatekeeper, one owner: the seam must not split into a receipted-
        but-unenforced daemon path when Phase 2 wires decisions into Engine."""
        gk = RecordingGatekeeper()
        session = self._session(config_files, monkeypatch, gk)
        assert session.gatekeeper is gk
        engine = Engine(session)  # how SessionServer and the CLI construct it
        assert engine.gatekeeper is gk


class TestAgentAttachment:
    def _build(self, config_files: Path, monkeypatch: pytest.MonkeyPatch, **kwargs):
        from access_control.config import load_inventory, load_operations
        from access_control.daemon import build_session

        monkeypatch.setenv("AC_DATA_DIR", str(config_files.parent / "data"))
        inventory = load_inventory(config_files / "inventory.yaml")
        catalog = load_operations(config_files / "operations.yaml")
        return build_session("lin01", inventory=inventory, catalog=catalog, **kwargs)

    @staticmethod
    def _human_env(monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("AC_AGENT_ID", "CLAUDECODE", "CLAUDE_CODE"):
            monkeypatch.delenv(var, raising=False)

    def test_a_plain_session_is_not_agent_attached(
        self, config_files: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._human_env(monkeypatch)
        session = self._build(config_files, monkeypatch)
        assert session.agent_attached is False
        assert session.tainted is False

    def test_an_explicit_agent_id_marks_the_session_agent_attached(
        self, config_files: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._human_env(monkeypatch)
        session = self._build(config_files, monkeypatch, agent_id="claude-agent-1")
        assert session.agent_attached is True

    def test_a_claude_code_environment_marks_the_session_agent_attached(
        self, config_files: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._human_env(monkeypatch)
        monkeypatch.setenv("CLAUDECODE", "1")
        session = self._build(config_files, monkeypatch)
        assert session.agent_attached is True


class TestSinkOrdering:
    def test_the_sink_fires_inside_the_audit_lock(self, tmp_path: Path) -> None:
        """Concurrent daemon threads share one AuditLog; the sink must run
        under the same lock that assigned the record's seq, or the mirrored
        ledger can chain records in a different order than the JSONL."""
        log = AuditLog(session_id="SES-test", agent_id="AGT-test",
                       directory=tmp_path / "logs")

        held: list[bool] = []

        def sink(**fields: Any) -> None:
            held.append(log._lock._is_owned())  # CPython RLock introspection

        log.sink = sink
        log.action("SESSION_START")
        assert held == [True]
