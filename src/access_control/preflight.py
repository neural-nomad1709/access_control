"""Checks that run before any work, and can be re-run at any point.

Two distinct jobs.

**Is the connection still real?**  A session object can look healthy while the
path underneath it has gone: a bastion dropped an idle connection, a tunnel died,
the WinRM runspace timed out.  Trusting the object rather than the wire means a
step "fails" for reasons that have nothing to do with the step.

**Are we on the machine we think we are?**  This is the one that matters most and
is easiest to skip.  Every hop past the first is reached through a *local port
forward*, and a local port is just a number: a stale tunnel, a reused port, or a
transposed digit in an inventory entry all produce a healthy-looking session
pointed at the wrong server.  Nothing downstream can detect that -- the commands
succeed, on the wrong host.  So identity is verified by asking the machine its own
name and comparing it with what was expected.

Everything here is read-only and cheap enough to run repeatedly.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .errors import AccessControlError
from .session import Session

FATAL = "fatal"
WARNING = "warning"

#: A round trip that takes longer than this is reported, not failed -- a slow
#: link is a fact worth knowing before starting a long operation.
SLOW_ROUND_TRIP_S = 5.0


@dataclass
class CheckResult:
    """One preflight answer."""

    name: str
    passed: bool
    detail: str
    severity: str = FATAL
    duration_s: float = 0.0
    #: What the operator should do about it, when it failed.
    remedy: str = ""

    @property
    def blocking(self) -> bool:
        return not self.passed and self.severity == FATAL

    def to_dict(self) -> dict[str, Any]:
        data = {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "severity": self.severity,
            "duration_s": round(self.duration_s, 2),
        }
        if self.remedy:
            data["remedy"] = self.remedy
        return data

    def line(self) -> str:
        mark = "ok  " if self.passed else ("FAIL" if self.severity == FATAL else "warn")
        return f"[{mark}] {self.name}: {self.detail}"


@dataclass
class PreflightReport:
    """The full set of answers, and whether work may begin."""

    host_id: str
    checks: list[CheckResult] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return not any(check.blocking for check in self.checks)

    @property
    def blockers(self) -> list[CheckResult]:
        return [check for check in self.checks if check.blocking]

    @property
    def warnings(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed and c.severity == WARNING]

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "ok": self.ok,
            "checks": [c.to_dict() for c in self.checks],
            "blockers": [c.name for c in self.blockers],
            "warnings": [c.name for c in self.warnings],
            "duration_s": round(self.duration_s, 2),
        }

    def render(self) -> str:
        lines = [c.line() for c in self.checks]
        for check in self.blockers:
            if check.remedy:
                lines += ["", f"  -> {check.remedy}"]
        lines += ["", "PREFLIGHT PASSED" if self.ok else "PREFLIGHT FAILED -- no work was started"]
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Connection liveness
# --------------------------------------------------------------------------


def check_session_live(session: Session) -> CheckResult:
    """Is the session object itself usable -- open, not expired, not closed?"""
    started = time.monotonic()
    try:
        session.require_active()
    except AccessControlError as exc:
        return CheckResult(
            "session.live",
            False,
            str(exc).splitlines()[0],
            duration_s=time.monotonic() - started,
            remedy=f"Reconnect in your own terminal:  uv run ac connect {session.host_id}",
        )
    remaining = session.idle_timeout_s - session.idle_s if session.idle_timeout_s else None
    detail = "session open"
    if remaining is not None:
        detail += f", expires in {int(remaining)}s of inactivity"
    return CheckResult("session.live", True, detail, duration_s=time.monotonic() - started)


def check_chain_intact(session: Session) -> CheckResult:
    """Is every SSH hop still connected?

    Checked separately from the round trip so a broken *hop* is distinguishable
    from a target that has stopped answering -- they have different remedies.
    """
    started = time.monotonic()
    hops = getattr(session, "ssh_hops", [])
    dead = [hop.node_id for hop in hops if not hop.active]
    if dead:
        return CheckResult(
            "chain.intact",
            False,
            f"SSH transport dropped on: {', '.join(dead)}",
            duration_s=time.monotonic() - started,
            remedy=(
                f"A hop dropped, usually an idle timeout on the bastion. "
                f"Reconnect:  uv run ac connect {session.host_id}"
            ),
        )
    names = [hop.node_id for hop in hops] or ["(none)"]
    return CheckResult(
        "chain.intact",
        True,
        f"{len(hops)} SSH hop(s) active: {', '.join(names)}",
        duration_s=time.monotonic() - started,
    )


def check_round_trip(session: Session) -> CheckResult:
    """Prove the target actually answers, rather than assuming it does.

    The cheapest possible command, run for its round trip rather than its
    output. A session can look open while the far end has gone away.
    """
    started = time.monotonic()
    command = "$true" if session.host.is_windows else "true"
    try:
        result = session.exec(command, timeout_s=45)
    except AccessControlError as exc:
        return CheckResult(
            "target.responds",
            False,
            f"no response: {exc}",
            duration_s=time.monotonic() - started,
            remedy=f"Reconnect:  uv run ac connect {session.host_id}",
        )
    elapsed = time.monotonic() - started
    if result.timed_out or result.exit_code is None:
        return CheckResult(
            "target.responds",
            False,
            "the target did not complete a trivial command",
            duration_s=elapsed,
            remedy=f"Reconnect:  uv run ac connect {session.host_id}",
        )
    if elapsed > SLOW_ROUND_TRIP_S:
        return CheckResult(
            "target.responds",
            True,
            f"responded in {elapsed:.1f}s -- slower than usual; long operations may drag",
            severity=WARNING,
            duration_s=elapsed,
        )
    return CheckResult(
        "target.responds", True, f"round trip {elapsed:.2f}s", duration_s=elapsed
    )


def check_identity(session: Session, expected: str | None = None) -> CheckResult:
    """Confirm the machine on the far end is the one we meant to reach.

    The single most valuable check here. Every hop past the first arrives over a
    local port forward, and a port number carries no identity: a stale tunnel, a
    reused port, or one wrong digit in an inventory address all produce a session
    that works perfectly -- against the wrong server. Commands succeed. Nothing
    downstream notices.

    ``expected`` is matched case-insensitively against the reported name, and a
    short name matches its own FQDN (``WIN-TARGET02`` matches
    ``win-target02.corp.net``), because the two are used interchangeably in most
    inventories.
    """
    started = time.monotonic()
    command = "$env:COMPUTERNAME" if session.host.is_windows else "hostname"
    try:
        result = session.exec(command, timeout_s=45)
    except AccessControlError as exc:
        return CheckResult(
            "target.identity",
            False,
            f"could not ask the host its name: {exc}",
            duration_s=time.monotonic() - started,
        )

    reported = (result.stdout or "").strip().splitlines()[0].strip() if result.stdout else ""
    elapsed = time.monotonic() - started

    if not reported:
        return CheckResult(
            "target.identity",
            False,
            "the host did not report a name",
            duration_s=elapsed,
            remedy="Check the target is healthy; a machine that cannot name itself is unwell.",
        )

    if not expected:
        return CheckResult(
            "target.identity",
            True,
            f"reported name '{reported}' (nothing to compare -- set expect_hostname to pin it)",
            severity=WARNING,
            duration_s=elapsed,
        )

    if _names_match(reported, expected):
        return CheckResult(
            "target.identity", True, f"confirmed '{reported}'", duration_s=elapsed
        )

    return CheckResult(
        "target.identity",
        False,
        f"WRONG HOST: expected '{expected}', connected to '{reported}'",
        duration_s=elapsed,
        remedy=(
            "Stop. Nothing further should run. This usually means a stale or reused local "
            "port forward, or a wrong address in inventory.yaml. Disconnect, check "
            "`ac routes <host>`, and reconnect before doing anything else."
        ),
    )


def _names_match(reported: str, expected: str) -> bool:
    """Case-insensitive comparison that tolerates short name vs FQDN."""
    left, right = reported.strip().lower(), expected.strip().lower()
    if left == right:
        return True
    return left.split(".")[0] == right.split(".")[0]


# --------------------------------------------------------------------------
# Resource and state checks
# --------------------------------------------------------------------------


def check_disk_space(session: Session, min_gb: float, drive: str | None = None) -> CheckResult:
    """Is there room to do the work?  Cheapest failure to catch early."""
    started = time.monotonic()
    if session.host.is_windows:
        letter = (drive or "C").rstrip(":")
        command = (
            f"$d = Get-PSDrive {letter} -ErrorAction Stop; "
            f'"FREE_GB={{0:N2}}" -f ($d.Free / 1GB)'
        )
    else:
        path = drive or "/"
        # `-P` forces POSIX output, where column 4 is always Available. Without
        # it the layouts differ: AIX puts Free in column 3 and %Used in 4, so a
        # plain `df -k` reads "96%" as the free space and reports 0.00 GB on a
        # host with terabytes. Found on a real AIX box.
        command = (
            f"df -Pk {path} 2>/dev/null | awk 'NR==2 {{printf \"FREE_GB=%.2f\\n\", $4/1048576}}'"
        )

    try:
        result = session.exec(command, timeout_s=60)
    except AccessControlError as exc:
        return CheckResult("disk.space", False, str(exc), duration_s=time.monotonic() - started)

    match = re.search(r"FREE_GB=([\d.]+)", result.stdout or "")
    elapsed = time.monotonic() - started
    if not match:
        return CheckResult(
            "disk.space",
            False,
            f"could not read free space ({(result.stdout or result.stderr or '').strip()[:120]})",
            severity=WARNING,
            duration_s=elapsed,
        )

    free = float(match.group(1))
    target = drive or ("C:" if session.host.is_windows else "/")
    if free < min_gb:
        return CheckResult(
            "disk.space",
            False,
            f"{target} has {free:.2f} GB free, need {min_gb} GB",
            duration_s=elapsed,
            remedy=f"Free space on {target} before starting, or install elsewhere.",
        )
    return CheckResult(
        "disk.space", True, f"{target} has {free:.2f} GB free (need {min_gb})", duration_s=elapsed
    )


def check_services_running(session: Session, names: Sequence[str]) -> CheckResult:
    """Are the services that must already be up, up?"""
    started = time.monotonic()
    if not names:
        return CheckResult("services.running", True, "none required")

    if session.host.is_windows:
        quoted = ",".join(f"'{n}'" for n in names)
        command = (
            f"foreach ($n in @({quoted})) {{ "
            f"$s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
            f'if ($s) {{ "{{0}}={{1}}" -f $n, $s.Status }} else {{ "$n=MISSING" }} }}'
        )
    else:
        checks = "; ".join(
            f"(systemctl is-active {n} >/dev/null 2>&1 && echo '{n}=Running') "
            f"|| (lssrc -s {n} 2>/dev/null | grep -q active && echo '{n}=Running') "
            f"|| echo '{n}=NotRunning'"
            for n in names
        )
        command = checks

    try:
        result = session.exec(command, timeout_s=90)
    except AccessControlError as exc:
        return CheckResult(
            "services.running", False, str(exc), duration_s=time.monotonic() - started
        )

    text = result.stdout or ""
    bad = [n for n in names if not re.search(rf"{re.escape(n)}\s*=\s*Running", text, re.I)]
    elapsed = time.monotonic() - started
    if bad:
        return CheckResult(
            "services.running",
            False,
            f"not running: {', '.join(bad)}",
            duration_s=elapsed,
            remedy="Start them, or remove them from the brief's preflight if not truly required.",
        )
    return CheckResult(
        "services.running", True, f"running: {', '.join(names)}", duration_s=elapsed
    )


def check_pending_reboot(session: Session) -> CheckResult:
    """A pending reboot makes installs and patches behave unpredictably."""
    started = time.monotonic()
    if not session.host.is_windows:
        return CheckResult("no.pending_reboot", True, "not applicable on this platform")

    command = (
        "$p = $false; "
        "if (Get-Item 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based "
        "Servicing\\RebootPending' -ErrorAction SilentlyContinue) { $p = $true }; "
        "if (Get-Item 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto "
        "Update\\RebootRequired' -ErrorAction SilentlyContinue) { $p = $true }; "
        '"PENDING=$p"'
    )
    try:
        result = session.exec(command, timeout_s=60)
    except AccessControlError as exc:
        return CheckResult(
            "no.pending_reboot", False, str(exc), severity=WARNING,
            duration_s=time.monotonic() - started,
        )

    elapsed = time.monotonic() - started
    if "PENDING=True" in (result.stdout or ""):
        return CheckResult(
            "no.pending_reboot",
            False,
            "a reboot is already pending on this host",
            duration_s=elapsed,
            remedy=(
                "Installing over a pending reboot produces failures that look like package "
                "problems. Reboot first (with the operator's approval), then retry."
            ),
        )
    return CheckResult("no.pending_reboot", True, "no reboot pending", duration_s=elapsed)


def check_no_active_install(session: Session) -> CheckResult:
    """Another installer already running is MSI error 1618, caught early."""
    started = time.monotonic()
    if not session.host.is_windows:
        return CheckResult("no.active_install", True, "not applicable on this platform")

    command = (
        "$p = Get-Process msiexec, setup, wusa -ErrorAction SilentlyContinue | "
        "Where-Object { $_.SessionId -ne $null }; "
        '"COUNT=" + (@($p).Count)'
    )
    try:
        result = session.exec(command, timeout_s=60)
    except AccessControlError as exc:
        return CheckResult(
            "no.active_install", False, str(exc), severity=WARNING,
            duration_s=time.monotonic() - started,
        )

    elapsed = time.monotonic() - started
    match = re.search(r"COUNT=(\d+)", result.stdout or "")
    count = int(match.group(1)) if match else 0
    # msiexec runs as a service permanently; more than a couple means real activity.
    if count > 2:
        return CheckResult(
            "no.active_install",
            False,
            f"{count} installer process(es) already running",
            severity=WARNING,
            duration_s=elapsed,
            remedy="Wait for the running install to finish, or you will get MSI error 1618.",
        )
    return CheckResult(
        "no.active_install", True, "no installer appears to be running", duration_s=elapsed
    )


def check_custom(session: Session, name: str, command: str, expect: str | None) -> CheckResult:
    """An arbitrary read-only check declared by the brief.

    Policy still applies: a check that tries to change something is refused.
    """
    from . import safety

    started = time.monotonic()
    verdict = safety.classify(command)
    if verdict.level != safety.ALLOWED:
        return CheckResult(
            f"custom.{name}",
            False,
            f"refused: a preflight check must be read-only ({verdict.reason})",
            duration_s=time.monotonic() - started,
            remedy="Preflight checks verify state; they do not change it. Move this to a step.",
        )

    try:
        result = session.exec(command, timeout_s=120)
    except AccessControlError as exc:
        return CheckResult(
            f"custom.{name}", False, str(exc), duration_s=time.monotonic() - started
        )

    elapsed = time.monotonic() - started
    output = (result.stdout or "").strip()
    if expect is not None and expect not in output:
        return CheckResult(
            f"custom.{name}",
            False,
            f"expected output to contain {expect!r}, got: {output[:200] or '(empty)'}",
            duration_s=elapsed,
        )
    if expect is None and not result.ok:
        return CheckResult(
            f"custom.{name}",
            False,
            f"exit code {result.exit_code}: {output[:200]}",
            duration_s=elapsed,
        )
    return CheckResult(f"custom.{name}", True, output[:160] or "ok", duration_s=elapsed)


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def run_preflight(session: Session, spec: Mapping[str, Any] | None = None) -> PreflightReport:
    """Run the connection checks, then whatever the brief asked for.

    Ordering is deliberate: liveness before identity, identity before anything
    that touches the host's state. There is no point measuring disk space on a
    machine that turns out to be the wrong one.
    """
    spec = dict(spec or {})
    started = time.monotonic()
    report = PreflightReport(host_id=session.host_id)

    def add(check: CheckResult) -> bool:
        report.checks.append(check)
        return not check.blocking

    # --- always, in this order ------------------------------------------
    if not add(check_session_live(session)):
        report.duration_s = time.monotonic() - started
        return report
    if not add(check_chain_intact(session)):
        report.duration_s = time.monotonic() - started
        return report
    if not add(check_round_trip(session)):
        report.duration_s = time.monotonic() - started
        return report
    if not add(check_identity(session, spec.get("expect_hostname"))):
        report.duration_s = time.monotonic() - started
        return report

    # --- declared by the brief -------------------------------------------
    if spec.get("require_free_disk_gb") is not None:
        add(
            check_disk_space(
                session, float(spec["require_free_disk_gb"]), spec.get("disk_drive")
            )
        )
    if spec.get("require_services_running"):
        add(check_services_running(session, list(spec["require_services_running"])))

    abort_if = [str(a).lower() for a in (spec.get("abort_if") or [])]
    if "pending_reboot" in abort_if:
        add(check_pending_reboot(session))
    if "active_msi_install" in abort_if or "active_install" in abort_if:
        add(check_no_active_install(session))

    for custom in spec.get("checks") or []:
        add(
            check_custom(
                session,
                str(custom.get("name", "unnamed")),
                str(custom.get("run", "")),
                custom.get("expect_contains"),
            )
        )

    report.duration_s = time.monotonic() - started
    return report
