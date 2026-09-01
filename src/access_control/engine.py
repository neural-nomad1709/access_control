"""Operation execution.

The engine deliberately stays dumb.  It renders a step, checks it against
policy, runs it, decides whether the result met the declared expectation, and --
when it did not -- gathers the diagnostics the operation author nominated.  Then
it hands all of that back as structured data and stops.

It does **not** try to fix anything.  Deciding what a failure means and what to
do about it is the agent's job, and it has the logs, the exit code and the hint
to do it with.  That division is what PLAN.md's "read logs on each action and
take further action to resolve any issues" actually requires: a reliable
observation layer, not a clever one.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import safety
from .audit import (
    EV_BLOCKED,
    EV_COLLECT,
    EV_COMMAND,
    EV_OPERATION_END,
    EV_OPERATION_START,
    EV_PERMISSION,
    EV_STEP_END,
    EV_STEP_START,
)
from .config import (
    CollectSpec,
    Expect,
    Operation,
    Step,
    operation_variables,
    unresolved_variables,
)
from .errors import CommandBlocked, ConfigError, PermissionRequired
from .gatekeeper import Gatekeeper, NullGatekeeper, spiffe_actor
from .redact import redact
from .session import Session
from .template import render
from .transport.base import ExecResult
from .transport.pshell import quote_single

MAX_COLLECT_CHARS = 6000


# --------------------------------------------------------------------------
# Outcomes
# --------------------------------------------------------------------------


@dataclass
class StepOutcome:
    """What happened when one step ran -- the unit an agent reasons over."""

    step_id: str
    desc: str
    command: str
    status: str = "pending"  # ok | failed | skipped | blocked | dry-run
    result: ExecResult | None = None
    expectation_met: bool = False
    expectation_reason: str = ""
    collected: list[dict[str, Any]] = field(default_factory=list)
    hint: str | None = None
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "dry-run", "skipped")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "step_id": self.step_id,
            "desc": self.desc,
            "status": self.status,
            "ok": self.ok,
            "command": redact(self.command),
            "expectation_met": self.expectation_met,
            "duration_s": round(self.duration_s, 2),
        }
        if self.expectation_reason:
            data["expectation_reason"] = self.expectation_reason
        if self.result is not None:
            result = self.result.to_dict()
            result.pop("command", None)
            data.update(result)
        if self.collected:
            data["collected_logs"] = self.collected
        if self.hint:
            data["hint"] = self.hint
        return data


@dataclass
class OperationOutcome:
    """The result of running one operation, start to finish."""

    operation_id: str
    host_id: str
    session_id: str
    agent_id: str
    steps: list[StepOutcome] = field(default_factory=list)
    status: str = "pending"  # ok | failed | dry-run | blocked
    stopped_at: str | None = None
    duration_s: float = 0.0
    params: Mapping[str, Any] = field(default_factory=dict)
    route: str = ""
    started_at: str = ""
    #: Where the shareable summary was written, if it was.
    summary_file: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "dry-run")

    @property
    def failed_step(self) -> StepOutcome | None:
        return next((s for s in self.steps if s.status in ("failed", "blocked")), None)

    def report_markdown(self) -> str:
        """A shareable end-to-end summary of this run.

        PLAN.md asks for a summary after each operation that the product hands to
        the user.  It is written for someone who was not watching: what ran,
        where, whether it worked, and -- if it did not -- the evidence and the
        next action, without needing to read the raw audit trail.
        """
        verdict = {
            "ok": "SUCCEEDED",
            "failed": "FAILED",
            "blocked": "BLOCKED BY POLICY",
            "dry-run": "DRY RUN (nothing was executed)",
        }.get(self.status, self.status.upper())

        lines = [
            f"# Operation report: {self.operation_id}",
            "",
            f"**Result:** {verdict}",
            "",
            f"| | |",
            f"| --- | --- |",
            f"| Host | `{self.host_id}` |",
            f"| Route | {self.route or '-'} |",
            f"| Started | {self.started_at or '-'} |",
            f"| Duration | {round(self.duration_s, 2)}s |",
            f"| Session | `{self.session_id}` |",
            f"| Agent | `{self.agent_id}` |",
        ]
        if self.params:
            rendered = ", ".join(f"{k}={v}" for k, v in self.params.items())
            lines.append(f"| Parameters | {rendered} |")
        lines += ["", "## Steps", "", "| # | Step | Result | Exit | Duration |", "| --- | --- | --- | --- | --- |"]

        for i, step in enumerate(self.steps, 1):
            exit_code = "-"
            if step.result is not None and step.result.exit_code is not None:
                exit_code = str(step.result.exit_code)
            lines.append(
                f"| {i} | {step.step_id} — {step.desc} | {step.status} | {exit_code} "
                f"| {round(step.duration_s, 1)}s |"
            )

        skipped = []
        if self.stopped_at:
            reached = {s.step_id for s in self.steps}
            skipped = [s.step_id for s in self.steps if s.step_id not in reached]

        failed = self.failed_step
        if failed is not None:
            lines += [
                "",
                f"## Why it stopped: `{failed.step_id}`",
                "",
                f"{failed.expectation_reason or 'the step did not meet its expectation'}",
            ]
            if failed.result is not None and failed.result.stdout.strip():
                lines += ["", "**Output**", "", "```", failed.result.stdout.strip()[-2000:], "```"]
            for line in (failed.result.ps_errors if failed.result else [])[:5]:
                lines += ["", "**Error stream**", "", "```", line[:1000], "```"]
            for entry in failed.collected:
                lines += [
                    "",
                    f"**Collected: {entry.get('source')}**",
                    "",
                    "```",
                    (entry.get("content") or entry.get("error") or "")[:2000],
                    "```",
                ]
            if failed.hint:
                lines += ["", f"**Hint:** {failed.hint}"]
            lines += [
                "",
                "**Next action:** investigate with `run_command` / `ac exec`, fix the cause, "
                f"then re-run from this step only:",
                "",
                "```",
                f"uv run ac run {self.host_id} {self.operation_id} --confirm --start-at {failed.step_id}",
                "```",
            ]
        elif self.status == "ok":
            lines += ["", "All steps met their declared expectations. No action required."]

        if skipped:
            lines += ["", f"**Not reached:** {', '.join(skipped)}"]

        lines += ["", "---", "", f"Full audit trail: session `{self.session_id}`."]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "operation_id": self.operation_id,
            "host_id": self.host_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "status": self.status,
            "ok": self.ok,
            "duration_s": round(self.duration_s, 2),
            "params": dict(self.params),
            "steps": [s.to_dict() for s in self.steps],
        }
        if self.route:
            data["route"] = self.route
        if self.summary_file:
            data["summary_file"] = self.summary_file
        # The shareable report travels with the result so an agent can relay it
        # to the operator verbatim rather than paraphrasing what happened.
        data["summary"] = self.report_markdown()
        if self.stopped_at:
            data["stopped_at"] = self.stopped_at
            failed = self.failed_step
            if failed is not None:
                data["next_action"] = (
                    f"Step '{failed.step_id}' failed. Read 'collected_logs' and 'hint' on that "
                    f"step, then either fix the cause with run_command and re-run the "
                    f"operation from that step (start_at='{failed.step_id}'), or report the "
                    f"blocker to the operator. Share 'summary' with them either way."
                )
        return data


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class Engine:
    """Runs operations and ad-hoc commands against one session."""

    def __init__(self, session: Session, gatekeeper: "Gatekeeper | None" = None) -> None:
        self.session = session
        self.audit = session.audit
        # The session owns the gatekeeper (build_session sets it); an explicit
        # argument overrides, and with neither this engine is ungoverned.
        self.gatekeeper: Gatekeeper = (
            gatekeeper or getattr(session, "gatekeeper", None) or NullGatekeeper()
        )
        self._report_seq = 0

    # -- planning ---------------------------------------------------------

    def preview(self, operation_id: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Render every command without connecting to anything.

        This is what an agent shows the operator when asking for permission: the
        exact commands, and any that policy would block or gate.
        """
        op = self._operation(operation_id)
        variables = operation_variables(op, self.session.host, params or {})
        missing = unresolved_variables(op, variables)
        if missing:
            raise ConfigError(
                f"operation '{op.id}': step templates reference {', '.join(missing)}, which is "
                f"neither a declared parameter nor a host variable."
            )

        steps: list[dict[str, Any]] = []
        for step in op.steps:
            command = render(step.run, variables, where=f"{op.id}.{step.id}")
            verdict = safety.classify(command)
            steps.append(
                {
                    "step_id": step.id,
                    "desc": step.desc,
                    "shell": step.shell,
                    "command": command,
                    "policy": verdict.level,
                    "policy_reason": verdict.reason,
                    "destructive": step.destructive,
                    "timeout_s": step.timeout_s,
                }
            )

        return {
            "operation_id": op.id,
            "host_id": self.session.host_id,
            "description": op.description,
            "route": self.session.route.describe(),
            "requires_permission": op.is_gated,
            "destructive": op.destructive,
            "params": dict(variables),
            "steps": steps,
        }

    # -- execution --------------------------------------------------------

    def run_operation(
        self,
        operation_id: str,
        params: Mapping[str, Any] | None = None,
        *,
        confirmed: bool = False,
        dry_run: bool = False,
        only_steps: Sequence[str] | None = None,
        start_at: str | None = None,
    ) -> OperationOutcome:
        """Run an operation's steps in order, stopping at the first failure.

        ``only_steps`` and ``start_at`` exist for the remediate-and-retry loop:
        after fixing what broke, re-running the whole operation from the top is
        usually wrong (and sometimes destructive).
        """
        op = self._operation(operation_id)
        variables = operation_variables(op, self.session.host, params or {})
        started = time.monotonic()

        outcome = OperationOutcome(
            operation_id=op.id,
            host_id=self.session.host_id,
            session_id=self.session.session_id,
            agent_id=self.session.agent_id,
            params={k: v for k, v in (params or {}).items()},
            route=getattr(self.session.route, "describe", lambda: "")(),
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

        # An out-of-band approval covers these exact rendered commands, the
        # same consent an operator's --confirm expresses — so it satisfies the
        # per-step confirm gate for gated commands inside the operation.
        confirmed = self._check_permission(op, params or {}, confirmed, dry_run) or confirmed

        if self.audit:
            self.audit.emit(
                EV_OPERATION_START,
                operation_id=op.id,
                params=dict(params or {}),
                confirmed=confirmed,
                dry_run=dry_run,
                steps=[s.id for s in op.steps],
            )

        selected = self._select_steps(op, only_steps, start_at)
        for step in selected:
            step_outcome = self.run_step(
                op, step, variables, confirmed=confirmed, dry_run=dry_run
            )
            outcome.steps.append(step_outcome)
            if not step_outcome.ok and not step.continue_on_failure:
                outcome.stopped_at = step.id
                break

        outcome.duration_s = time.monotonic() - started
        if dry_run:
            outcome.status = "dry-run"
        elif outcome.stopped_at:
            failed = outcome.failed_step
            outcome.status = "blocked" if failed and failed.status == "blocked" else "failed"
        else:
            outcome.status = "ok"

        outcome.summary_file = self._write_report(outcome)

        if self.audit:
            self.audit.emit(
                EV_OPERATION_END,
                operation_id=op.id,
                status=outcome.status,
                stopped_at=outcome.stopped_at,
                duration_s=round(outcome.duration_s, 2),
                steps_run=len(outcome.steps),
                summary_file=outcome.summary_file,
            )
        return outcome

    def _write_report(self, outcome: OperationOutcome) -> str | None:
        """Persist the shareable summary next to the audit trail.

        Written even when the run failed -- especially then. Never raises: losing
        the report must not turn a recoverable failure into an exception.
        """
        if self.audit is None or self.audit.directory is None:
            return None
        self._report_seq += 1
        name = f"{outcome.session_id}-{self._report_seq:02d}-{outcome.operation_id}.md"
        path = Path(self.audit.directory) / name
        try:
            path.write_text(outcome.report_markdown(), encoding="utf-8")
        except OSError:
            return None
        return str(path)

    def run_step(
        self,
        op: Operation,
        step: Step,
        variables: Mapping[str, Any],
        *,
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> StepOutcome:
        """Render, police, run, judge, and (on failure) collect diagnostics."""
        command = render(step.run, variables, where=f"{op.id}.{step.id}")
        outcome = StepOutcome(step_id=step.id, desc=step.desc, command=command)
        started = time.monotonic()

        if self.audit:
            self.audit.emit(
                EV_STEP_START,
                operation_id=op.id,
                step_id=step.id,
                desc=step.desc,
                shell=step.shell,
                command=command,
                dry_run=dry_run,
            )

        if dry_run:
            # Nothing is sent anywhere, so policy is reported rather than
            # enforced -- the whole point of a dry run is to see what *would*
            # happen, including which steps will need the operator's approval.
            verdict = safety.classify(command)
            outcome.status = "dry-run"
            outcome.expectation_met = True
            outcome.expectation_reason = (
                "" if verdict.level == safety.ALLOWED else f"would require: {verdict.explain()}"
            )
            outcome.duration_s = time.monotonic() - started
            return outcome

        # A gated command inside an operation the operator already approved is
        # allowed -- that approval covered these exact commands, which
        # `preview()` showed them. A *blocked* command is refused regardless.
        # Governance policy (identity-bound, default-deny) runs first; the
        # deny-list stays exactly where it is, as the last line.
        try:
            self._authorize(f"{op.id}.{step.id}", {"command": command})
            safety.check(command, confirmed=confirmed)
        except (CommandBlocked, PermissionRequired) as exc:
            outcome.status = "blocked"
            outcome.expectation_reason = str(exc)
            outcome.duration_s = time.monotonic() - started
            if self.audit:
                self.audit.emit(EV_BLOCKED, operation_id=op.id, step_id=step.id, reason=str(exc))
            return outcome

        result = self._scan_result(
            self.session.exec(command, shell=step.shell, timeout_s=step.timeout_s)
        )
        outcome.result = result
        met, reason = evaluate(step, result, variables)
        outcome.expectation_met = met
        outcome.expectation_reason = reason
        outcome.status = "ok" if met else "failed"

        if not met:
            outcome.collected = self.collect(step, result)
            if step.on_failure is not None:
                outcome.hint = step.on_failure.hint_for(result.exit_code)

        outcome.duration_s = time.monotonic() - started
        if self.audit:
            self.audit.action(
                "SCRIPT_EXECUTE",
                event=EV_STEP_END,
                source="local",
                target=self.session.host_id,
                result="SUCCESS" if outcome.ok else "FAILURE",
                detail=f"{op.id}/{step.id}",
                operation_id=op.id,
                step_id=step.id,
                ok=outcome.ok,
                exit_code=result.exit_code,
                duration_s=round(outcome.duration_s, 2),
                expectation_reason=reason,
                stdout_chars=len(result.stdout),
                collected=len(outcome.collected),
                hint=outcome.hint,
            )
        return outcome

    def run_command(
        self,
        command: str,
        *,
        shell: str | None = None,
        confirmed: bool = False,
        timeout_s: int = 300,
    ) -> ExecResult:
        """Ad-hoc command -- the escape hatch used while diagnosing a failure."""
        try:
            self._authorize("ac_exec", {"command": command})
            safety.check(command, confirmed=confirmed)
        except (CommandBlocked, PermissionRequired) as exc:
            if self.audit:
                self.audit.action(
                    "COMMAND_BLOCKED",
                    event=EV_BLOCKED,
                    target=self.session.host_id,
                    result="BLOCKED",
                    detail=command,
                    reason=str(exc),
                )
            raise

        result = self._scan_result(
            self.session.exec(command, shell=shell, timeout_s=timeout_s)
        )
        if self.audit:
            self.audit.action(
                "COMMAND_EXECUTE",
                event=EV_COMMAND,
                target=self.session.host_id,
                result="SUCCESS" if result.ok else "FAILURE",
                detail=command,
                shell=shell,
                confirmed=confirmed,
                exit_code=result.exit_code,
                duration_s=round(result.duration_s, 2),
            )
        return result

    # -- governance -------------------------------------------------------

    def _actor(self) -> str:
        return spiffe_actor(self.session.agent_id)

    def _authorize(self, tool: str, args: Mapping[str, Any]) -> None:
        """P1: identity-bound default-deny policy, before anything is sent."""
        decision = self.gatekeeper.authorize(
            self._actor(), tool, args, self.session.session_id)
        if not decision.allowed:
            raise CommandBlocked(
                f"refused by governance policy: {decision.reason or 'default deny'}"
            )

    def _scan_result(self, result: ExecResult) -> ExecResult:
        """P3: remote output through the gatekeeper before any caller sees it.

        Redactions replace the text in place; a hostile finding taints the
        session, which widens the approval net for the rest of it.
        """
        verdict = self.gatekeeper.scan_output(
            result.stdout or "", self._actor(), self.session.session_id)
        if verdict.tainted and not getattr(self.session, "tainted", False):
            self.session.tainted = True
            if self.audit:
                self.audit.emit(
                    "session.tainted",
                    findings=list(verdict.findings),
                    detail="hostile content in collected output; approvals widened",
                )
        if verdict.text != (result.stdout or ""):
            result.stdout = verdict.text
        return result

    # -- diagnostics ------------------------------------------------------

    def collect(self, step: Step, result: ExecResult) -> list[dict[str, Any]]:
        """Gather what the operation author nominated for this failure."""
        if step.on_failure is None or not step.on_failure.collect:
            return []

        collected: list[dict[str, Any]] = []
        for spec in step.on_failure.collect:
            collected.extend(self._collect_one(spec))

        if self.audit and collected:
            self.audit.action(
                "LOG_COLLECT",
                event=EV_COLLECT,
                target=self.session.host_id,
                detail=f"{len(collected)} source(s) after {step.id}",
                step_id=step.id,
                sources=[c.get("source") for c in collected],
                exit_code=result.exit_code,
            )
        return collected

    def _collect_one(self, spec: CollectSpec) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        windows = self.session.host.is_windows

        for pattern in spec.files:
            command = (
                _windows_tail_command(pattern, spec.tail_lines)
                if windows
                else f"tail -n {spec.tail_lines} {pattern} 2>/dev/null"
            )
            out.append(self._collect_command(command, source=pattern, kind="file"))

        if spec.eventlog and windows:
            log_name = str(spec.eventlog.get("log", "Application"))
            newest = int(spec.eventlog.get("newest", 25))
            level = spec.eventlog.get("level")
            command = _windows_eventlog_command(log_name, newest, level)
            out.append(
                self._collect_command(command, source=f"eventlog:{log_name}", kind="eventlog")
            )
        elif spec.eventlog and not windows:
            out.append(
                self._collect_command(
                    f"journalctl -n {int(spec.eventlog.get('newest', 25))} --no-pager 2>/dev/null "
                    f"|| tail -n {int(spec.eventlog.get('newest', 25))} /var/log/syslog 2>/dev/null",
                    source="journal",
                    kind="eventlog",
                )
            )

        if spec.command:
            out.append(self._collect_command(spec.command, source="command", kind="command"))

        return out

    def _collect_command(self, command: str, *, source: str, kind: str) -> dict[str, Any]:
        """Run one diagnostic command, never letting it derail the report."""
        entry: dict[str, Any] = {"source": source, "kind": kind}
        try:
            safety.check(command, confirmed=False)
        except Exception as exc:  # noqa: BLE001 - a bad collector is a config bug, not an outage
            entry["error"] = f"collector refused by policy: {exc}"
            return entry
        try:
            result = self.session.exec(command, timeout_s=120)
        except Exception as exc:  # noqa: BLE001 - the failure being diagnosed matters more
            entry["error"] = f"could not collect: {exc}"
            return entry

        text = (result.stdout or "").strip() or (result.stderr or "").strip()
        if len(text) > MAX_COLLECT_CHARS:
            text = text[-MAX_COLLECT_CHARS:]
            entry["truncated"] = True
        if text:
            # P3: collected logs are exactly the channel prompt injection and
            # leaked credentials arrive on; scan before the caller reads them.
            verdict = self.gatekeeper.scan_output(
                text, self._actor(), self.session.session_id)
            if verdict.tainted:
                self.session.tainted = True
            text = verdict.text
        entry["content"] = text or "(empty)"
        entry["exit_code"] = result.exit_code
        return entry

    # -- helpers ----------------------------------------------------------

    def _operation(self, operation_id: str) -> Operation:
        op = self.session.catalog.get(operation_id)
        if not op.applies_to(self.session.host):
            raise ConfigError(
                f"operation '{operation_id}' is not permitted on host "
                f"'{self.session.host_id}'. Its host_ids are "
                f"{list(op.host_ids) or 'unset'} and tags {list(op.tags) or 'unset'}; "
                f"'{self.session.host_id}' has tags {list(self.session.host.tags) or 'none'}."
            )
        if not self.session.permits(operation_id):
            raise PermissionRequired(
                f"operation '{operation_id}' was not in the list authorised for this session "
                f"({', '.join(self.session.allowed_operations)}). Reconnect with it included:\n"
                f"    uv run ac connect {self.session.host_id} --ops {operation_id}"
            )
        return op

    def _check_permission(
        self, op: Operation, params: Mapping[str, Any], confirmed: bool, dry_run: bool
    ) -> bool:
        """Gate the operation; returns True when an out-of-band approval was
        granted (it carries the weight of an operator's --confirm)."""
        # A tainted session (hostile content arrived in collected output) can
        # no longer be trusted to drive even normally-allowed operations
        # unattended: everything gates until the session ends.
        gated = op.is_gated or getattr(self.session, "tainted", False)
        agent_attached = getattr(self.session, "agent_attached", False)

        if dry_run or not gated or (confirmed and not agent_attached):
            if self.audit and not dry_run:
                self.audit.emit(
                    EV_PERMISSION,
                    operation_id=op.id,
                    gated=gated,
                    confirmed=confirmed,
                    granted=True,
                )
            return False

        # Rendered with the operator's actual parameters: approving
        # "apt-get install -y {{package}}" is not informed consent.
        preview = self.preview(op.id, params)
        commands = "\n".join(f"  [{s['step_id']}] {s['command']}" for s in preview["steps"])

        if agent_attached:
            # An agent cannot self-approve with any flag (--confirm included):
            # the gate files a held request a human resolves out of band — in
            # the governance control plane or the operator shell — and a
            # timeout is a denial. One approval authorizes one run.
            ticket = self.gatekeeper.request_approval(
                self._actor(), op.id, commands, self.session.session_id)
            if ticket.status == "approved":
                if self.audit:
                    self.audit.action(
                        "PERMISSION_REQUEST",
                        event=EV_PERMISSION,
                        target=self.session.host_id,
                        result="SUCCESS",
                        detail=f"{op.id} approved out of band ({ticket.request_id})",
                        operation_id=op.id,
                        request_id=ticket.request_id,
                        gated=True,
                        granted=True,
                    )
                return True
            pending = ticket.status == "pending"
            if self.audit:
                self.audit.action(
                    "PERMISSION_REQUEST",
                    event=EV_PERMISSION,
                    target=self.session.host_id,
                    result="PENDING" if pending else "BLOCKED",
                    detail=f"{op.id} {ticket.status} ({ticket.request_id})",
                    operation_id=op.id,
                    request_id=ticket.request_id,
                    gated=True,
                    granted=False,
                )
            if pending:
                raise PermissionRequired(
                    f"operation '{op.id}' on host '{self.session.host_id}' is held for "
                    f"out-of-band approval (request {ticket.request_id}).\n"
                    f"A human resolves it with `:approve` in the operator shell or in the "
                    f"governance control plane; re-run once resolved. The request lapses "
                    f"into a denial if nobody acts. Commands awaiting approval:\n{commands}"
                )
            raise PermissionRequired(
                f"operation '{op.id}' on host '{self.session.host_id}' was refused: "
                f"approval request {ticket.request_id} is {ticket.status}. "
                f"A lapsed or denied request never runs; file a new run to ask again."
            )

        if self.audit:
            self.audit.action(
                "PERMISSION_REQUEST",
                event=EV_PERMISSION,
                target=self.session.host_id,
                result="BLOCKED",
                detail=f"{op.id} awaiting operator approval",
                operation_id=op.id,
                gated=True,
                confirmed=False,
                granted=False,
            )
        raise PermissionRequired(
            f"operation '{op.id}' on host '{self.session.host_id}' needs the operator's "
            f"approval before it runs"
            + (" (it is marked destructive)" if op.destructive else "")
            + ".\nShow them exactly this, and re-run with confirmation once they agree:\n"
            f"{commands}"
        )

    @staticmethod
    def _select_steps(
        op: Operation, only_steps: Sequence[str] | None, start_at: str | None
    ) -> list[Step]:
        steps = list(op.steps)
        known = {s.id for s in steps}

        if only_steps:
            unknown = [s for s in only_steps if s not in known]
            if unknown:
                raise ConfigError(
                    f"operation '{op.id}' has no step(s) {', '.join(unknown)}. "
                    f"Steps are: {', '.join(sorted(known))}"
                )
            return [s for s in steps if s.id in set(only_steps)]

        if start_at:
            if start_at not in known:
                raise ConfigError(
                    f"operation '{op.id}' has no step '{start_at}'. "
                    f"Steps are: {', '.join(s.id for s in steps)}"
                )
            index = next(i for i, s in enumerate(steps) if s.id == start_at)
            return steps[index:]

        return steps


# --------------------------------------------------------------------------
# Expectation evaluation
# --------------------------------------------------------------------------


def resolve_expect(step: Step, variables: Mapping[str, Any] | None, where: str) -> Expect:
    """Render ``{{placeholders}}`` inside an expectation.

    Expectations are templated for the same reason commands are: an operation
    that installs ``{{package}}`` usually wants to confirm the output mentions
    ``{{package}}``, and a literal ``{{package}}`` would never match.
    """
    expect = step.expect
    if not variables:
        return expect
    return replace(
        expect,
        stdout_contains=(
            render(expect.stdout_contains, variables, where=where)
            if expect.stdout_contains
            else None
        ),
        stdout_not_contains=(
            render(expect.stdout_not_contains, variables, where=where)
            if expect.stdout_not_contains
            else None
        ),
        stdout_regex=(
            render(expect.stdout_regex, variables, where=where) if expect.stdout_regex else None
        ),
    )


def evaluate(
    step: Step, result: ExecResult, variables: Mapping[str, Any] | None = None
) -> tuple[bool, str]:
    """Did ``result`` satisfy ``step``'s declared expectation?

    Returns ``(met, reason)``; the reason is written for whoever has to act on a
    failure, so it always names the expected and the actual value.
    """
    expect = resolve_expect(step, variables, where=f"expect:{step.id}")

    if result.timed_out:
        return False, f"timed out after {step.timeout_s}s"

    if not expect.any_exit_code and expect.exit_code is not None:
        if result.exit_code != expect.exit_code:
            return (
                False,
                f"expected exit code {expect.exit_code}, got {result.exit_code}",
            )

    if expect.stdout_contains and expect.stdout_contains not in result.stdout:
        return False, f"stdout does not contain {expect.stdout_contains!r}"

    if expect.stdout_not_contains and expect.stdout_not_contains in result.stdout:
        return False, f"stdout unexpectedly contains {expect.stdout_not_contains!r}"

    if expect.stdout_regex and not re.search(expect.stdout_regex, result.stdout, re.MULTILINE):
        return False, f"stdout does not match /{expect.stdout_regex}/"

    return True, "expectation met"


# --------------------------------------------------------------------------
# Diagnostic command builders
# --------------------------------------------------------------------------


def tail_command(pattern: str, lines: int, *, windows: bool) -> str:
    """Build a command that shows the last ``lines`` of ``pattern``.

    Shared by failure collection and the ``fetch_log`` tool so both behave
    identically -- including resolving a glob to its most recent match.
    """
    if windows:
        return _windows_tail_command(pattern, lines)
    return (
        f"tail -n {int(lines)} {pattern} 2>/dev/null || "
        f"echo 'no such file or not readable: {pattern}'"
    )


def _windows_tail_command(pattern: str, lines: int) -> str:
    """Tail the most recently written file matching ``pattern``.

    Installers write timestamped log names (``MSI a1b2c.LOG``), so a glob that
    resolves to the newest match is what actually finds the failure.
    """
    return (
        f"$m = Get-ChildItem -Path {quote_single(pattern)} -ErrorAction SilentlyContinue | "
        f"Sort-Object LastWriteTime -Descending | Select-Object -First 1; "
        f"if ($m) {{ \"--- $($m.FullName) ---\"; "
        f"Get-Content -Path $m.FullName -Tail {lines} -ErrorAction SilentlyContinue }} "
        f"else {{ \"no file matched {pattern}\" }}"
    )


def _windows_eventlog_command(log_name: str, newest: int, level: Any) -> str:
    level_filter = ""
    if level:
        mapping = {"error": 2, "warning": 3, "information": 4, "critical": 1}
        numeric = mapping.get(str(level).lower())
        if numeric:
            level_filter = f"; Level={numeric}"
    return (
        f"Get-WinEvent -FilterHashtable @{{LogName={quote_single(log_name)}{level_filter}}} "
        f"-MaxEvents {newest} -ErrorAction SilentlyContinue | "
        f"Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message | "
        f"Format-List"
    )
