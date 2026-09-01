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
        ticket = gk.request_approval("a", "t", "cmd", "s")
        assert ticket.status == "approved"
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
    def test_build_session_attaches_the_gatekeepers_receipt_sink(
        self, config_files: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from access_control.config import load_inventory, load_operations
        from access_control.daemon import build_session

        monkeypatch.setenv("AC_DATA_DIR", str(config_files.parent / "data"))
        inventory = load_inventory(config_files / "inventory.yaml")
        catalog = load_operations(config_files / "operations.yaml")
        gk = RecordingGatekeeper()
        session = build_session(
            "lin01", inventory=inventory, catalog=catalog, gatekeeper=gk,
        )
        session.audit.action("ROUTE_RESOLVE", target="lin01")
        assert [r["action"] for r in gk.receipts] == ["ROUTE_RESOLVE"]
