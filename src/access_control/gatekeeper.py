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

import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

_SPIFFE_UNSAFE = re.compile(r"[^a-z0-9._-]")


def spiffe_actor(agent_id: str, org: str = "access-control") -> str:
    """The SPIFFE identity a governance plane keys policy and receipts on.

    Lowercased and sanitized to AL's path grammar ([a-z0-9._-]): ac agent ids
    like ``AGT-20260812-3f9a1c`` or ``user@host-3fa`` must map to identities
    the governance plane's registry could actually issue.
    """
    return f"spiffe://{org}/agent/{_SPIFFE_UNSAFE.sub('-', str(agent_id).lower())}"


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
        # No external plane exists to hold an approval, so nothing here may
        # claim one was granted: "not_governed" tells the engine to fall back
        # to the confirm gate — today's behaviour, never an auto-approval.
        return ApprovalTicket(request_id="null", status="not_governed")

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

    ``receipt()`` mirrors every canonical audit action into AL's
    Ed25519-signed, hash-chained ledger (verifiable offline with
    ``al-verify``); ``authorize()`` applies the identity-bound default-deny
    tool policy; ``request_approval()`` holds gated work for out-of-band human
    resolution (one approval, bound to the exact rendered commands, authorizes
    one run; timeout is a denial); ``scan_output()`` screens collected output
    and taints the session on hostile content.

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
        tool_policy_path: str | Path | None = None,
    ) -> None:
        from al_core.embed import Runtime

        if admin_api_token is None:
            # Only AL's HTTP control plane uses this token; an embedded runtime
            # never serves HTTP, so an unguessable throwaway satisfies it.
            admin_api_token = secrets.token_hex(16)
        data_dir = Path(data_dir)
        self._org = org
        overrides: dict[str, Any] = {
            # AL's default signing-key path is CWD-relative; left alone, the
            # embedded runtime would drop a raw Ed25519 private key wherever
            # the process started (a git repo root, say). Key material lives
            # under data_dir, full stop.
            "keys": {"signing_key_path": str(data_dir / "keys" / "mediator_ed25519")},
        }
        if tool_policy_path is not None:
            # AL's default here is CWD-relative too; a missing file means
            # deny-all, so the operator names the policy explicitly.
            overrides["policy"] = {"tool_policy_path": str(tool_policy_path)}
        self._runtime = Runtime(
            config_path,
            data_dir=str(data_dir),
            admin_api_token=admin_api_token,
            **overrides,
        )
        self._ledger_path = data_dir / "ledger.jsonl"
        # One held approval per (session, tool, exact rendered commands): the
        # ticket the engine polls by re-running. Binding to the commands means
        # an approval for one command line can never authorize another.
        # Resolution consumes it — one approval, one run. Rehydrated from AL's
        # store so a daemon restart cannot orphan a pending request.
        self._held: dict[tuple[str, str, str], str] = {}
        for request in self._runtime.action_gate.hitl.pending():
            self._held[
                (request.session or "", request.tool,
                 self._commands_key(request.detail or ""))
            ] = request.request_id

    # -- decisions -----------------------------------------------------------

    def authorize(self, actor: str, tool: str, args: Mapping[str, Any],
                  session: str) -> GateDecision:
        """Default-deny tool policy + argument constraints, receipted by AL."""
        outcome = self._runtime.action_gate.authorize(
            actor, tool, dict(args), session_id=session)
        if outcome.allowed:
            return GateDecision(allowed=True)
        findings = ", ".join(
            f.get("rule_id", "?") for f in (outcome.decision.findings or []))
        return GateDecision(
            allowed=False,
            reason=f"{outcome.decision.block_reason or 'DENIED'}"
                   + (f" ({findings})" if findings else ""),
        )

    @staticmethod
    def _commands_key(rendered_commands: str) -> str:
        import hashlib

        return hashlib.sha256(rendered_commands.encode("utf-8")).hexdigest()

    def request_approval(self, actor: str, tool: str, rendered_commands: str,
                         session: str) -> ApprovalTicket:
        """File or poll the held approval for these exact rendered commands.

        First call submits a pending request carrying the commands (resolved
        out of band via the AL control plane or the operator shell);
        subsequent calls with the same commands poll it. A resolution or lapse
        consumes the request — one approval authorizes one run of exactly what
        was approved, and timeout remains a denial.
        """
        hitl = self._runtime.action_gate.hitl
        key = (session, tool, self._commands_key(rendered_commands))
        request_id = self._held.get(key)
        if request_id is None:
            request = hitl.submit(actor, tool, detail=rendered_commands,
                                  session=session)
            self._held[key] = request.request_id
            return ApprovalTicket(request_id=request.request_id, status="pending")
        status = hitl.status(request_id)
        if status == "pending":
            return ApprovalTicket(request_id=request_id, status="pending")
        del self._held[key]  # resolved or lapsed: consumed either way
        return ApprovalTicket(request_id=request_id, status=status)

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Pending requests, for the operator shell's :approve verb. ``detail``
        is what will actually run — the approver reads it, not the tool name."""
        hitl = self._runtime.action_gate.hitl
        return [{
            "request_id": r.request_id,
            "actor": r.actor,
            "tool": r.tool,
            "detail": r.detail,
            "session": r.session,
            "remaining_s": hitl.remaining_s(r.request_id),
        } for r in hitl.pending()]

    def resolve_approval(self, request_id: str, decision: str, *, by: str) -> bool:
        """Resolve one held request (allow | deny); receipted with the resolver."""
        hitl = self._runtime.action_gate.hitl
        resolved = (hitl.approve(request_id, by=by) if decision == "allow"
                    else hitl.deny(request_id, by=by))
        if resolved:
            self._runtime.record(
                actor=by, action="permission_request", target=f"hitl:{request_id}",
                verdict="allow" if decision == "allow" else "block",
                block_reason=None if decision == "allow" else "HITL_DENIED",
            )
        return resolved

    def scan_output(self, text: str, actor: str, session: str) -> ScanVerdict:
        """Collected output through AL's content gate before the caller sees it.

        Secrets/PII strip on top of ac's own redaction registry; an injection
        finding taints the session (widening the approval net) and the hostile
        text is withheld, never delivered.
        """
        result = self._runtime.action_gate.scan_result(
            text, actor=actor, tool="collect", session_id=session)
        tainted = self._runtime.action_gate.taint.is_tainted(session)
        if result.blocked:
            reason = result.block_reason or "CONTENT_BLOCKED"
            return ScanVerdict(
                text=f"[content withheld by the governance plane: {reason}]",
                findings=tuple(f.get("rule_id", "?") for f in result.findings),
                tainted=tainted,
            )
        return ScanVerdict(
            text=result.text,
            findings=tuple(f.get("rule_id", "?") for f in result.findings),
            tainted=tainted,
        )

    # -- evidence -----------------------------------------------------------

    def receipt(self, **fields: Any) -> None:
        """Mirror one canonical audit record into the signed ledger.

        Synchronous by design: a failed append raises into the audit path —
        evidence must not be eventually consistent.
        """
        action = str(fields.get("action", ""))
        verdict = _RECEIPT_VERDICTS.get(str(fields.get("result", "SUCCESS")), "block")
        target = fields.get("target") or fields.get("host_id") or ""
        self._runtime.record(
            actor=spiffe_actor(fields.get("agentId", "unknown"), self._org),
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
    "spiffe_actor",
]
