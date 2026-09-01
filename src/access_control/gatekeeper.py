"""The Gatekeeper seam — external governance as an optional plug-in.

A Gatekeeper is the single interface through which an outside governance plane
can see and shape what this tool does: authorize a call before it runs, hold a
gated operation for out-of-band human approval, scan collected output before it
reaches the caller, and mirror every canonical audit action into its own
(signed) ledger.

`NullGatekeeper` is the default and the compatibility contract: everything
allowed, approvals granted (the existing `--confirm` gate remains the actual
control), output untouched, receipts dropped. A plain install behaves exactly
as if this module did not exist, with zero new dependencies.

`LighthouseGatekeeper` (the optional `access-control[lighthouse]` extra) backs
the same interface with an embedded AgentLighthouse runtime. Dependency
direction: this module imports nothing from this package; the daemon constructs
a gatekeeper and hands it down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable


@dataclass(frozen=True)
class GateDecision:
    """Verdict on one pre-execution authorization."""

    allowed: bool
    reason: str = ""


@dataclass(frozen=True)
class ApprovalTicket:
    """A held approval: resolved out of band, polled by request_id."""

    request_id: str
    status: str  # pending | approved | denied | timed_out


@dataclass(frozen=True)
class ScanVerdict:
    """Outcome of scanning collected output before it reaches the caller."""

    text: str
    findings: tuple[str, ...] = ()
    tainted: bool = False


@runtime_checkable
class Gatekeeper(Protocol):
    def authorize(self, actor: str, tool: str, args: Mapping[str, Any],
                  session: str) -> GateDecision: ...

    def request_approval(self, actor: str, tool: str, rendered_commands: str,
                         session: str) -> ApprovalTicket: ...

    def scan_output(self, text: str, actor: str, session: str) -> ScanVerdict: ...

    def receipt(self, **fields: Any) -> None: ...


class NullGatekeeper:
    """Today's behaviour: no external plane, nothing gated, nothing mirrored."""

    def authorize(self, actor: str, tool: str, args: Mapping[str, Any],
                  session: str) -> GateDecision:
        return GateDecision(allowed=True)

    def request_approval(self, actor: str, tool: str, rendered_commands: str,
                         session: str) -> ApprovalTicket:
        # The confirm gate in engine._check_permission is the real control
        # here; this ticket just says "no external gate objects".
        return ApprovalTicket(request_id="null", status="approved")

    def scan_output(self, text: str, actor: str, session: str) -> ScanVerdict:
        return ScanVerdict(text=text)

    def receipt(self, **fields: Any) -> None:
        return None


__all__ = [
    "ApprovalTicket",
    "GateDecision",
    "Gatekeeper",
    "NullGatekeeper",
    "ScanVerdict",
]
