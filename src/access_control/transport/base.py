"""The result type every channel returns, and the protocol they implement."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..redact import redact

#: Remote output is capped before it reaches an agent's context window.  A
#: runaway ``Get-EventLog`` can produce megabytes; the head and tail are what
#: carry the diagnosis, so the middle is dropped rather than the end.
MAX_OUTPUT_CHARS = 20_000


def clamp_output(text: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    """Trim ``text`` to ``limit`` characters, keeping the head and the tail.

    Returns ``(text, truncated)``.
    """
    if text is None:
        return "", False
    if len(text) <= limit:
        return text, False
    head = limit * 2 // 3
    tail = limit - head
    omitted = len(text) - head - tail
    return (
        f"{text[:head]}\n\n... [{omitted} characters omitted] ...\n\n{text[-tail:]}",
        True,
    )


@dataclass
class ExecResult:
    """The outcome of one remote command.

    This is the structure an agent reads to decide what to do next, so it keeps
    the PowerShell streams separate: an installer that writes its real diagnosis
    to the error stream while exiting 0 is common, and collapsing everything into
    one blob would hide it.
    """

    node_id: str
    channel: str
    command: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    ps_errors: list[str] = field(default_factory=list)
    ps_warnings: list[str] = field(default_factory=list)
    ps_verbose: list[str] = field(default_factory=list)
    ps_information: list[str] = field(default_factory=list)
    truncated: bool = False
    timed_out: bool = False

    def __post_init__(self) -> None:
        self.command = redact(self.command)
        self.stdout, out_trunc = clamp_output(redact(self.stdout or ""))
        self.stderr, err_trunc = clamp_output(redact(self.stderr or ""))
        self.truncated = self.truncated or out_trunc or err_trunc
        for name in ("ps_errors", "ps_warnings", "ps_verbose", "ps_information"):
            setattr(self, name, [redact(str(v)) for v in getattr(self, name)])

    @property
    def ok(self) -> bool:
        """Exit code 0 and the command actually completed."""
        return self.exit_code == 0 and not self.timed_out

    @property
    def had_errors(self) -> bool:
        """True if anything wrote to an error stream, regardless of exit code."""
        return bool(self.ps_errors) or bool(self.stderr.strip())

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form, as returned to the agent."""
        data: dict[str, Any] = {
            "node_id": self.node_id,
            "channel": self.channel,
            "command": self.command,
            "exit_code": self.exit_code,
            "ok": self.ok,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_s": round(self.duration_s, 2),
        }
        if self.ps_errors:
            data["ps_errors"] = self.ps_errors
        if self.ps_warnings:
            data["ps_warnings"] = self.ps_warnings
        if self.ps_verbose:
            data["ps_verbose"] = self.ps_verbose
        if self.ps_information:
            data["ps_information"] = self.ps_information
        if self.truncated:
            data["truncated"] = True
        if self.timed_out:
            data["timed_out"] = True
        return data

    def summary_line(self) -> str:
        state = "ok" if self.ok else (f"exit {self.exit_code}" if not self.timed_out else "TIMED OUT")
        return f"[{self.node_id}/{self.channel}] {state} in {self.duration_s:.1f}s"


@runtime_checkable
class Channel(Protocol):
    """What every transport can do."""

    node_id: str
    kind: str

    def exec(self, command: str, *, shell: str = "powershell", timeout_s: int = 600) -> ExecResult:
        """Run ``command`` and return its result."""
        ...

    def upload(self, local_path: str, remote_path: str) -> None:
        """Copy a local file to the remote machine."""
        ...

    def fetch(self, remote_path: str, local_path: str) -> None:
        """Copy a remote file to the local machine."""
        ...

    def close(self) -> None:
        """Release the connection."""
        ...
