"""PowerShell script wrapping.

Two problems this solves.

**Exit codes.**  PowerShell has no single notion of "the exit code".  A native
tool sets ``$LASTEXITCODE``; a cmdlet throws; ``powershell.exe -EncodedCommand``
exits 0 unless the script says otherwise; and PSRP has no process exit code at
all.  Every script is therefore wrapped so it prints a sentinel line carrying the
resolved code, which both the SSH and WinRM channels parse back out.  An MSI
returning 1603 or 3010 reaches the agent as a number it can act on.

**Quoting.**  Remote command lines get mangled by whichever shells they pass
through.  For SSH the wrapped script is sent as UTF-16LE base64 via
``-EncodedCommand``, so nothing in it can be misinterpreted on the way.

Streams are deliberately *not* merged: an installer that writes its real
diagnosis to the error stream while exiting 0 is common, and ``*>&1`` would bury
it in stdout.
"""

from __future__ import annotations

import base64
import re

EXIT_SENTINEL = "__AC_EXIT__"
_SENTINEL_RE = re.compile(rf"^{EXIT_SENTINEL}:(-?\d+)\s*$", re.MULTILINE)


def wrap_script(script: str, *, out_string: bool = False) -> str:
    """Wrap a user script so it reports a resolved exit code.

    ``$ErrorActionPreference`` is left at its default: forcing ``Stop`` would
    abort scripts that legitimately produce non-terminating errors (``Get-Item``
    on a missing path while probing, for instance).  A thrown terminating error
    is caught and reported as exit 1.

    ``out_string`` pipes the success stream through ``Out-String``, which is what
    PSRP needs: without it, a ``PSCustomObject`` comes back to Python as a type
    name rather than the readable table an operator (or an agent) expects.  It
    only touches the success pipeline, so the error and warning streams stay
    separate and still arrive intact.
    """
    body = (
        ["    & {", script, "    } | Out-String -Width 512"]
        if out_string
        else [script]
    )
    return "\n".join(
        [
            "$ProgressPreference = 'SilentlyContinue'",
            "$global:LASTEXITCODE = 0",
            "$__ac_exit = 0",
            "try {",
            *body,
            "    if ($null -ne $LASTEXITCODE) { $__ac_exit = $LASTEXITCODE } else { $__ac_exit = 0 }",
            "} catch {",
            "    Write-Error ($_ | Out-String)",
            "    $__ac_exit = 1",
            "}",
            f"Write-Output ('{EXIT_SENTINEL}:' + $__ac_exit)",
        ]
    )


def parse_exit(stdout: str) -> tuple[str, int | None]:
    """Strip the sentinel from ``stdout`` and return ``(clean_stdout, exit_code)``.

    Returns ``None`` for the code if the sentinel is absent -- the caller then
    falls back to whatever the transport reported.
    """
    if not stdout:
        return stdout or "", None
    matches = list(_SENTINEL_RE.finditer(stdout))
    if not matches:
        return stdout, None
    last = matches[-1]
    code = int(last.group(1))
    cleaned = _SENTINEL_RE.sub("", stdout).rstrip("\r\n")
    return cleaned, code


def encode_command(script: str) -> str:
    """Base64 UTF-16LE encoding for ``powershell.exe -EncodedCommand``."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def powershell_command_line(script: str) -> str:
    """A complete ``powershell.exe`` invocation carrying ``script`` safely."""
    return (
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {encode_command(wrap_script(script))}"
    )


def quote_single(value: str) -> str:
    """Quote a value for a PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"
