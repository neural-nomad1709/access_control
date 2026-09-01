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

import secrets
from dataclasses import dataclass
from pathlib import Path
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


# How canonical audit actions land in receipt-v1.1's closed vocabulary.
# Session-establishment events (route, hops, auth, tunnels, interactive
# launches) are all session_open; execution, transfer and collection are
# remote_exec; the original action always rides in the receipt target
# ("SSH_CONNECT:bastion1"), so nothing is flattened away. EVERY member of
# audit.ACTIONS has a deliberate entry — a cross-module test pins the two
# vocabularies together, so a new canonical action cannot silently fall
# through to the remote_exec default and sign a receipt claiming a remote
# command ran when none did.
_RECEIPT_ACTIONS = {
    "SESSION_START": "session_open",
    "ROUTE_RESOLVE": "session_open",
    "SSH_CONNECT": "session_open",
    "WINRM_CONNECT": "session_open",
    "AUTHENTICATE": "session_open",
    "TUNNEL_OPEN": "session_open",
    "RDP_LAUNCH": "session_open",
    "SESSION_END": "session_close",
    "PERMISSION_REQUEST": "permission_request",
    "COMMAND_EXECUTE": "remote_exec",
    "SCRIPT_EXECUTE": "remote_exec",
    "FILE_UPLOAD": "remote_exec",
    "FILE_DOWNLOAD": "remote_exec",
    "LOG_COLLECT": "remote_exec",
    "COMMAND_BLOCKED": "remote_exec",
    "ERROR": "remote_exec",
    # Emitted by the daemon but absent from audit.ACTIONS (F-12):
    "PREFLIGHT": "remote_exec",
    "COMMAND": "remote_exec",
}
_DEFAULT_RECEIPT_ACTION = "remote_exec"

# Audit results -> receipt verdicts. FAILURE maps to allow: the verdict is the
# mediation decision (the command was permitted), and the operational outcome
# stays in the JSONL trail and the receipt target.
_RECEIPT_VERDICTS = {
    "SUCCESS": "allow",
    "FAILURE": "allow",
    "BLOCKED": "block",
    "PENDING": "ask",
}
_BLOCK_REASONS = {"block": "TOOL_DENIED", "ask": "HITL_REQUIRED"}


class LighthouseGatekeeper:
    """Gatekeeper backed by an embedded AgentLighthouse runtime.

    Phase 1 scope: ``receipt()`` mirrors every canonical audit action into
    AL's Ed25519-signed, hash-chained ledger (verifiable offline with
    ``al-verify``). The decision methods still behave like ``NullGatekeeper``;
    enforcement arrives in Phase 2 behind the same interface.

    Requires the ``access-control[lighthouse]`` extra; constructing it without
    ``al_core`` installed raises ImportError.
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        data_dir: str | Path,
        admin_api_token: str | None = None,
        org: str = "access-control",
    ) -> None:
        from al_core.embed import Runtime

        if admin_api_token is None:
            # Only AL's HTTP control plane uses this token; an embedded runtime
            # never serves HTTP, so an unguessable throwaway satisfies it.
            admin_api_token = secrets.token_hex(16)
        data_dir = Path(data_dir)
        self._org = org
        self._runtime = Runtime(
            config_path,
            data_dir=str(data_dir),
            admin_api_token=admin_api_token,
            # AL's default signing-key path is CWD-relative; left alone, the
            # embedded runtime would drop a raw Ed25519 private key wherever
            # the process started (a git repo root, say). Key material lives
            # under data_dir, full stop.
            keys={"signing_key_path": str(data_dir / "keys" / "mediator_ed25519")},
        )
        self._ledger_path = data_dir / "ledger.jsonl"

    # -- decisions (Phase 2 wires these to AL's gates) ----------------------

    def authorize(self, actor: str, tool: str, args: Mapping[str, Any],
                  session: str) -> GateDecision:
        return GateDecision(allowed=True)

    def request_approval(self, actor: str, tool: str, rendered_commands: str,
                         session: str) -> ApprovalTicket:
        return ApprovalTicket(request_id="null", status="approved")

    def scan_output(self, text: str, actor: str, session: str) -> ScanVerdict:
        return ScanVerdict(text=text)

    # -- evidence -----------------------------------------------------------

    def receipt(self, **fields: Any) -> None:
        """Mirror one canonical audit record into the signed ledger.

        Synchronous by design: a failed append raises into the audit path —
        evidence must not be eventually consistent.
        """
        action = str(fields.get("action", ""))
        verdict = _RECEIPT_VERDICTS.get(str(fields.get("result", "SUCCESS")), "block")
        target = fields.get("target") or fields.get("host_id") or ""
        # Lowercased: AL's SPIFFE grammar accepts [a-z0-9._-] path segments
        # only, and receipts must carry actors its identity registry can issue.
        agent_id = str(fields.get("agentId", "unknown")).lower()
        self._runtime.record(
            actor=f"spiffe://{self._org}/agent/{agent_id}",
            action=_RECEIPT_ACTIONS.get(action, _DEFAULT_RECEIPT_ACTION),
            target=f"{action}:{target}",
            verdict=verdict,
            block_reason=_BLOCK_REASONS.get(verdict),
            session=fields.get("sessionId"),
        )

    @property
    def public_key(self):  # noqa: ANN201 — Ed25519PublicKey, an al-core type
        """The mediator public key an auditor verifies the ledger against."""
        return self._runtime.public_key

    @property
    def ledger_path(self):  # noqa: ANN201
        """The signed JSONL ledger file (feed it to ``al-verify``)."""
        return self._ledger_path

    def close(self) -> None:
        self._runtime.close()


__all__ = [
    "ApprovalTicket",
    "GateDecision",
    "Gatekeeper",
    "LighthouseGatekeeper",
    "NullGatekeeper",
    "ScanVerdict",
]
