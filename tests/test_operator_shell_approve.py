"""The :approve verb — resolving held approvals from the ac prompt (D3).

The operator holding the session is usually the human who must approve an
agent's gated operation; making them switch to the governance dashboard to
click allow would be a tax on the safe path. :approve lists and resolves the
same held requests the control plane serves — one HitlGate underneath.
"""

from __future__ import annotations

import io
from typing import Any

from rich.console import Console

from access_control.operator_shell import OperatorShell


class ApprovableGatekeeper:
    def __init__(self) -> None:
        self.pending = [{
            "request_id": "hitl_abc123", "actor": "spiffe://x/agent/claude",
            "tool": "install-app", "remaining_s": 120.0,
        }]
        self.resolutions: list[tuple[str, str, str]] = []

    def pending_approvals(self) -> list[dict[str, Any]]:
        return self.pending

    def resolve_approval(self, request_id: str, decision: str, *, by: str) -> bool:
        if any(r["request_id"] == request_id for r in self.pending):
            self.resolutions.append((request_id, decision, by))
            self.pending = [r for r in self.pending if r["request_id"] != request_id]
            return True
        return False


class ShellSession:
    """The slice of Session the :approve verb touches."""

    def __init__(self, gatekeeper: Any) -> None:
        self.gatekeeper = gatekeeper
        self.audit = None


def make_shell(gatekeeper: Any):
    out, err = io.StringIO(), io.StringIO()
    shell = OperatorShell(
        ShellSession(gatekeeper),
        Console(file=out, force_terminal=False, width=120),
        Console(file=err, force_terminal=False, width=120),
    )
    return shell, out, err


class TestApproveVerb:
    def test_bare_approve_lists_pending_requests(self) -> None:
        shell, out, _ = make_shell(ApprovableGatekeeper())
        shell._meta("approve")
        text = out.getvalue()
        assert "hitl_abc123" in text
        assert "install-app" in text

    def test_approve_resolves_and_names_the_operator(self) -> None:
        gk = ApprovableGatekeeper()
        shell, out, _ = make_shell(gk)
        shell._meta("approve hitl_abc123")
        assert len(gk.resolutions) == 1
        request_id, decision, by = gk.resolutions[0]
        assert (request_id, decision) == ("hitl_abc123", "allow")
        assert by.startswith("user:")

    def test_deny_resolves_as_a_denial(self) -> None:
        gk = ApprovableGatekeeper()
        shell, _, _ = make_shell(gk)
        shell._meta("deny hitl_abc123")
        assert gk.resolutions[0][1] == "deny"

    def test_an_unknown_request_reports_failure(self) -> None:
        shell, _, err = make_shell(ApprovableGatekeeper())
        shell._meta("approve hitl_nope")
        assert "could not" in err.getvalue().lower()

    def test_without_a_governance_plane_the_verb_explains_itself(self) -> None:
        from access_control.gatekeeper import NullGatekeeper

        shell, _, err = make_shell(NullGatekeeper())
        shell._meta("approve")
        assert "governance" in err.getvalue().lower()

    def test_help_mentions_the_verb(self) -> None:
        shell, out, _ = make_shell(ApprovableGatekeeper())
        shell._meta("help")
        assert ":approve" in out.getvalue()
