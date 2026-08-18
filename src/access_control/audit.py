"""Append-only audit trail.

PLAN.md requires that every activity is logged with an agent id, session id and
enough surrounding detail to "track back in case things go south".  Each action
appends one JSON object to ``<log_dir>/<session_id>.jsonl``, flushed immediately
so an abrupt termination still leaves a complete trail up to the last action.

Every value is passed through :mod:`.redact` on the way in, so a password can
never reach the log even if it is embedded in a command or an error message.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import ensure_dir, log_dir
from .redact import redact_obj

# Event names, kept in one place so the log stays greppable.
EV_SESSION_OPEN = "session.open"
EV_SESSION_CLOSE = "session.close"
EV_HOP_AUTH = "hop.auth"
EV_HOP_CONNECTED = "hop.connected"
EV_HOP_FAILED = "hop.failed"
EV_PROBE = "probe"
EV_OPERATION_START = "operation.start"
EV_OPERATION_END = "operation.end"
EV_STEP_START = "step.start"
EV_STEP_END = "step.end"
EV_COMMAND = "command"
EV_PERMISSION = "permission"
EV_BLOCKED = "command.blocked"
EV_COLLECT = "collect"
EV_TRANSFER = "transfer"
EV_RDP = "rdp.launch"
EV_ERROR = "error"


#: Canonical action names. Every meaningful thing the agent does is one of
#: these, so the trail can be filtered and correlated without parsing prose.
ACTIONS = (
    "ROUTE_RESOLVE",
    "SSH_CONNECT",
    "WINRM_CONNECT",
    "RDP_LAUNCH",
    "TUNNEL_OPEN",
    "AUTHENTICATE",
    "COMMAND_EXECUTE",
    "SCRIPT_EXECUTE",
    "FILE_UPLOAD",
    "FILE_DOWNLOAD",
    "LOG_COLLECT",
    "PERMISSION_REQUEST",
    "COMMAND_BLOCKED",
    "SESSION_START",
    "SESSION_END",
    "ERROR",
)

RESULT_SUCCESS = "SUCCESS"
RESULT_FAILURE = "FAILURE"
RESULT_BLOCKED = "BLOCKED"
RESULT_PENDING = "PENDING"


def new_session_id() -> str:
    """Sortable, unique session id: ``20260812T093015Z-a1b2c3d4``.

    Retained for callers that need a filename-safe id; the operator-facing
    identity is :class:`~.context.AgentIdentity`.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def default_agent_id() -> str:
    """Identify who is driving: an explicit id, or user@host as a fallback."""
    explicit = os.environ.get("AC_AGENT_ID")
    if explicit:
        return explicit
    if os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE"):
        return f"claude-code@{socket.gethostname()}"
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    return f"{user}@{socket.gethostname()}"


@dataclass
class AuditLog:
    """One session's audit trail."""

    session_id: str
    agent_id: str
    host_id: str | None = None
    directory: Path | None = None
    #: Filename-safe, sortable id. The operator-facing ``session_id``
    #: (``SES-845921``) is not sortable, and two sessions could in principle
    #: reuse it after the counter wraps, so files are named by this instead.
    trace_id: str | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        self.directory = ensure_dir(Path(self.directory) if self.directory else log_dir())
        stem = self.trace_id or self.session_id
        self.path = self.directory / f"{stem}.jsonl"
        self.records: list[dict[str, Any]] = []
        self._seq = 0
        self._lock = threading.Lock()
        self._started = time.time()

    # -- writing ----------------------------------------------------------

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one record.  Returns the record as written (redacted).

        The identity fields use the canonical spellings (``timestamp``,
        ``agentId``, ``sessionId``) so the trail drops straight into a SIEM
        without a transform step. Payload fields keep snake_case.
        """
        with self._lock:
            self._seq += 1
            record: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "seq": self._seq,
                "agentId": self.agent_id,
                "sessionId": self.session_id,
                "event": event,
            }
            if self.host_id:
                record["host_id"] = self.host_id
            record.update(redact_obj(fields))
            self.records.append(record)
            self._append(record)
            return record

    def action(
        self,
        action: str,
        *,
        source: str = "",
        target: str = "",
        result: str = RESULT_SUCCESS,
        event: str | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        """Record one canonical action.

        Every meaningful step -- a connection, an authentication, a command, a
        transfer, a refusal -- lands here with the same shape, so the trail can
        be filtered by ``action`` and correlated by ``source``/``target``
        without parsing free text::

            {"timestamp": "...", "agentId": "AGT-20260812-001",
             "sessionId": "SES-845921", "action": "SSH_CONNECT",
             "source": "JumpServer01", "target": "linux-app01",
             "result": "SUCCESS"}

        ``event`` overrides the derived event name, so an existing event stream
        (``step.end``) can carry a canonical action without emitting the record
        twice.
        """
        return self.emit(
            event or action.lower().replace("_", "."),
            action=action,
            source=source or "local",
            target=target,
            result=result,
            **fields,
        )

    def _append(self, record: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            # Losing the audit line must never abort the operation in progress;
            # the in-memory copy still backs `ac status`.
            pass

    def open_session(self, **fields: Any) -> None:
        self.action(
            "SESSION_START",
            event=EV_SESSION_OPEN,
            target=self.host_id or "",
            detail=str(fields.get("route", "")),
            client_host=socket.gethostname(),
            client_os=platform.platform(),
            pid=os.getpid(),
            **fields,
        )

    def error(self, message: str, **fields: Any) -> None:
        self.emit(EV_ERROR, message=message, **fields)

    # -- reading ----------------------------------------------------------

    def by_event(self, event: str) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("event") == event]

    @property
    def elapsed_s(self) -> float:
        return round(time.time() - self._started, 2)

    def timeline(self) -> list[dict[str, Any]]:
        """The execution trace: what happened, in order, with elapsed time.

        Invaluable when investigating a failure after the fact -- it answers
        "how far did it get, and how long did each stage take" without reading
        the full record set.
        """
        entries: list[dict[str, Any]] = []
        for record in self.records:
            action = record.get("action")
            if not action:
                continue
            entries.append(
                {
                    "timestamp": record.get("timestamp"),
                    "action": action,
                    "source": record.get("source"),
                    "target": record.get("target"),
                    "result": record.get("result"),
                    "detail": record.get("detail")
                    or record.get("endpoint")
                    or record.get("step_id")
                    or record.get("operation_id")
                    or "",
                    "duration_s": record.get("duration_s"),
                }
            )
        return entries

    def render_timeline(self) -> str:
        """The timeline as plain text, one line per action."""
        lines: list[str] = []
        for entry in self.timeline():
            stamp = str(entry.get("timestamp") or "")[11:19] or "--:--:--"
            arrow = ""
            if entry.get("source") and entry.get("target"):
                arrow = f" {entry['source']} -> {entry['target']}"
            detail = f"  {entry['detail']}" if entry.get("detail") else ""
            duration = f" ({entry['duration_s']}s)" if entry.get("duration_s") else ""
            result = entry.get("result")
            marker = "" if result in (None, "SUCCESS") else f" [{result}]"
            lines.append(f"{stamp}  {entry['action']:<20}{arrow}{detail}{duration}{marker}")
        return "\n".join(lines) or "(no actions recorded)"

    def summary(self) -> dict[str, Any]:
        """Machine-readable session summary, as ``ac status --json`` returns it."""
        steps = self.by_event(EV_STEP_END)
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "host_id": self.host_id,
            "elapsed_s": self.elapsed_s,
            "records": len(self.records),
            "steps_run": len(steps),
            "steps_ok": sum(1 for s in steps if s.get("ok")),
            "steps_failed": sum(1 for s in steps if not s.get("ok")),
            "errors": len(self.by_event(EV_ERROR)),
            "blocked": len(self.by_event(EV_BLOCKED)),
            "log_file": str(self.path),
        }

    # -- closing ----------------------------------------------------------

    def close(self, status: str = "closed", **fields: Any) -> Path:
        """Emit the closing record and write the human-readable summary."""
        self.action(
            "SESSION_END",
            event=EV_SESSION_CLOSE,
            target=self.host_id or "",
            result=RESULT_SUCCESS if status in ("closed", "idle-timeout") else RESULT_FAILURE,
            detail=status,
            status=status,
            **self.summary(),
            **fields,
        )
        return self.write_markdown_summary()

    def write_markdown_summary(self) -> Path:
        """Render a readable ``.md`` companion next to the JSONL trail."""
        summary = self.summary()
        md = self.path.with_suffix(".md")
        lines = [
            f"# Session {self.session_id}",
            "",
            f"- **Agent:** `{self.agent_id}`",
            f"- **Host:** `{self.host_id or '-'}`",
            f"- **Elapsed:** {summary['elapsed_s']}s",
            f"- **Steps:** {summary['steps_ok']} ok / {summary['steps_failed']} failed",
            f"- **Trail:** `{self.path}`",
            "",
        ]

        hops = [r for r in self.records if r.get("action") in ("SSH_CONNECT", "WINRM_CONNECT")]
        if hops:
            lines += ["## Hop chain", ""]
            for hop in hops:
                lines.append(
                    f"- `{hop.get('source')}` → `{hop.get('target')}` "
                    f"at {hop.get('endpoint')} over {hop.get('channel')} "
                    f"({hop.get('duration_s', '?')}s)"
                )
            lines.append("")

        timeline = self.render_timeline()
        if timeline != "(no actions recorded)":
            lines += ["## Execution timeline", "", "```", timeline, "```", ""]

        steps = self.by_event(EV_STEP_END)
        if steps:
            lines += [
                "## Steps",
                "",
                "| # | Operation | Step | Result | Exit | Duration |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
            for i, step in enumerate(steps, 1):
                result = "ok" if step.get("ok") else "FAILED"
                lines.append(
                    f"| {i} | {step.get('operation_id', '-')} | {step.get('step_id', '-')} "
                    f"| {result} | {step.get('exit_code', '-')} | {step.get('duration_s', '-')}s |"
                )
            lines.append("")

        errors = self.by_event(EV_ERROR)
        if errors:
            lines += ["## Errors", ""]
            lines += [f"- {e.get('message')}" for e in errors]
            lines.append("")

        try:
            md.write_text("\n".join(lines), encoding="utf-8")
        except OSError:
            pass
        return md


def load_session(session_id: str, directory: Path | None = None) -> list[dict[str, Any]]:
    """Read a past session's trail back off disk (for ``ac audit``)."""
    path = (directory or log_dir()) / f"{session_id}.jsonl"
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def list_sessions(directory: Path | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Recent sessions, newest first."""
    base = directory or log_dir()
    if not base.exists():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(base.glob("*.jsonl"), reverse=True)[:limit]:
        records = load_session(path.stem, base)
        opened = next((r for r in records if r.get("event") == EV_SESSION_OPEN), {})
        closed = next(
            (r for r in reversed(records) if r.get("event") == EV_SESSION_CLOSE), {}
        )
        out.append(
            {
                "trace_id": path.stem,
                "session_id": opened.get("sessionId", path.stem),
                "started": opened.get("timestamp"),
                "ended": closed.get("timestamp"),
                "agent_id": opened.get("agentId"),
                "host_id": opened.get("host_id"),
                "status": closed.get("status", "incomplete"),
                "steps_run": closed.get("steps_run", 0),
                "steps_failed": closed.get("steps_failed", 0),
            }
        )
    return out
