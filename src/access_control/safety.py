"""Command safety classification.

A last line of defence, checked immediately before anything is sent to a remote
machine, no matter which layer asked for it.  Two tiers:

``BLOCKED``
    Refused outright.  There is no legitimate reason for this utility to issue
    these, and no confirmation flag overrides them.

``CONFIRM``
    Allowed only with an explicit confirmation, which forces the agent to put
    the action in front of the operator first.

This is not a sandbox and does not pretend to be one -- an operator with a shell
can always do more damage than a pattern list can anticipate.  It exists to stop
an agent from turning a plausible-looking mistake into an outage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

BLOCKED = "blocked"
CONFIRM = "confirm"
ALLOWED = "allowed"


@dataclass(frozen=True)
class Rule:
    level: str
    pattern: re.Pattern[str]
    reason: str


def _rule(level: str, pattern: str, reason: str) -> Rule:
    return Rule(level, re.compile(pattern, re.IGNORECASE), reason)


#: Ordered; the first match wins, so BLOCKED rules come first.
RULES: tuple[Rule, ...] = (
    # -- irreversible destruction of storage ------------------------------
    _rule(BLOCKED, r"\bformat-(volume|disk)\b", "formats a volume"),
    _rule(BLOCKED, r"\bclear-disk\b", "erases a disk"),
    _rule(BLOCKED, r"\binitialize-disk\b", "reinitialises a disk"),
    _rule(BLOCKED, r"\bdiskpart\b.*\bclean\b", "diskpart clean destroys the partition table"),
    _rule(BLOCKED, r"\bmkfs(\.\w+)?\b", "creates a filesystem over existing data"),
    _rule(BLOCKED, r"\bdd\b[^\n|;]*\bof=/dev/(sd|nvme|hd|xvd)", "writes raw to a block device"),
    _rule(BLOCKED, r"\b(shred|wipefs)\b", "irreversibly wipes data"),
    # -- recursive deletion of a system root -------------------------------
    _rule(BLOCKED, r"\brm\b[^\n|;]*\s-[a-z]*[rR][a-z]*f|rm\b[^\n|;]*\s-[a-z]*f[a-z]*[rR]",
          "recursive forced delete"),
    _rule(BLOCKED, r"remove-item[^\n|;]*\b[a-z]:\\+\s*(-recurse|['\"]?\s*$)",
          "recursive delete of a drive root"),
    _rule(BLOCKED, r"\bdel\b[^\n|;]*/s[^\n|;]*\b[a-z]:\\+\s*$", "recursive delete of a drive root"),
    _rule(BLOCKED, r"get-childitem[^\n|;]*\|\s*remove-item[^\n|;]*-recurse[^\n|;]*-force",
          "pipeline recursive force delete"),
    # -- host takeover / self-harm ----------------------------------------
    _rule(BLOCKED, r":\(\)\s*\{\s*:\|\:&\s*\}\s*;\s*:", "fork bomb"),
    _rule(BLOCKED, r"\bchmod\b\s+-R\s+777\s+/\s*$", "world-writable root filesystem"),
    _rule(BLOCKED, r"\bcipher\b\s+/w", "overwrites free space, unrecoverable"),
    # -- disabling the protections this tool depends on --------------------
    _rule(BLOCKED, r"disable-psremoting", "would cut off the automation channel"),
    _rule(BLOCKED, r"(netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off)",
          "disables the host firewall entirely"),
    # -- allowed, but only with an explicit confirmation -------------------
    _rule(CONFIRM, r"\b(restart|stop)-computer\b", "reboots or shuts down the host"),
    _rule(CONFIRM, r"\bshutdown\b\s*(/|-)", "reboots or shuts down the host"),
    # Anchored to command position. A bare \breboot\b would match the word in a
    # comment such as "3010 = installed, needs a reboot", which is a description
    # of an exit code, not an instruction to reboot anything.
    _rule(
        CONFIRM,
        r"(?:^|[\n;&|]\s*|\bthen\s+|\bdo\s+)(reboot|halt|poweroff)\b",
        "reboots or shuts down the host",
    ),
    _rule(CONFIRM, r"\binit\b\s+[06]\b", "changes runlevel to halt or reboot"),
    _rule(CONFIRM, r"\b(stop|restart)-service\b", "interrupts a running service"),
    _rule(CONFIRM, r"\bsystemctl\b\s+(stop|restart|disable|mask)\b", "interrupts a running service"),
    _rule(CONFIRM, r"\bservice\b\s+\S+\s+(stop|restart)\b", "interrupts a running service"),
    _rule(CONFIRM, r"\b(install|uninstall)-windowsfeature\b", "changes installed server roles"),
    _rule(CONFIRM, r"\bremove-item\b", "deletes files"),
    # POSIX equivalents. Without these, `rm /etc/thing` ran ungated on a Unix
    # host while `Remove-Item` was gated on Windows -- found in live testing
    # against AIX. The block-list above still catches `rm -rf` outright.
    _rule(CONFIRM, r"(?:^|[\n;&|`(]\s*|\bsudo\s+)rm\b", "deletes files"),
    _rule(CONFIRM, r"(?:^|[\n;&|`(]\s*|\bsudo\s+)mv\b", "moves or overwrites files"),
    _rule(CONFIRM, r"\btruncate\b", "truncates a file"),
    _rule(CONFIRM, r"\b(chown|chgrp)\b", "changes file ownership"),
    _rule(CONFIRM, r"\bchmod\b", "changes file permissions"),
    _rule(CONFIRM, r"\b(kill|pkill|killall)\b", "terminates a running process"),
    _rule(CONFIRM, r"\bcrontab\b\s+(-r|-e|\S)", "changes scheduled jobs"),
    _rule(CONFIRM, r"\buninstall-", "removes installed software"),
    # `\b/x\b` would not match: the boundary before "/" fails after a space.
    _rule(CONFIRM, r"\bmsiexec\b[^\n|;]*[/-]x\b", "uninstalls a package"),
    _rule(CONFIRM, r"\bset-executionpolicy\b", "changes PowerShell script policy"),
    _rule(CONFIRM, r"\bnew-itemproperty\b[^\n|;]*hklm:", "writes to the machine registry hive"),
    _rule(CONFIRM, r"\bset-itemproperty\b[^\n|;]*hklm:", "writes to the machine registry hive"),
    _rule(CONFIRM, r"\breg\b\s+(add|delete)\b", "writes to the registry"),
    _rule(CONFIRM, r"\bdism\b[^\n|;]*/(add|remove)-package", "applies or removes a servicing package"),
    _rule(CONFIRM, r"\bwusa\b", "installs a Windows update package"),
    _rule(CONFIRM, r"\bnet\s+user\b[^\n|;]*\/(add|delete)", "creates or deletes a local account"),
    _rule(CONFIRM, r"\b(useradd|userdel|usermod)\b", "changes local accounts"),
    _rule(CONFIRM, r"\byum\b\s+(install|remove|update)|\b(apt|apt-get)\b\s+(install|remove|purge|upgrade)",
          "changes installed packages"),
)


@dataclass(frozen=True)
class Verdict:
    level: str
    reason: str | None = None
    pattern: str | None = None

    @property
    def is_blocked(self) -> bool:
        return self.level == BLOCKED

    @property
    def needs_confirmation(self) -> bool:
        return self.level == CONFIRM

    def explain(self) -> str:
        if self.level == ALLOWED:
            return "allowed"
        return f"{self.level}: {self.reason}"


_FULL_LINE_COMMENT = re.compile(r"^[ \t]*#.*$", re.MULTILINE)


def strip_comments(command: str) -> str:
    """Remove whole-line ``#`` comments before classification.

    Operation scripts are documented, and prose describing what an exit code
    means should not be policed as if it were an instruction.  Only entire
    comment lines are removed -- a ``#`` mid-line may be inside a string, and
    guessing wrong there would be worse than the false positive.
    """
    return _FULL_LINE_COMMENT.sub("", command)


def classify(command: str, extra_rules: Iterable[Rule] = ()) -> Verdict:
    """Classify ``command`` against the deny-list.  First match wins."""
    if not command or not command.strip():
        return Verdict(ALLOWED)
    subject = strip_comments(command)
    for rule in (*RULES, *extra_rules):
        if rule.pattern.search(subject):
            return Verdict(rule.level, rule.reason, rule.pattern.pattern)
    return Verdict(ALLOWED)


def check(command: str, *, confirmed: bool = False, extra_rules: Iterable[Rule] = ()) -> Verdict:
    """Classify and raise if the command may not run.

    Raises :class:`~.errors.CommandBlocked` for a blocked command, and
    :class:`~.errors.PermissionRequired` for one needing confirmation it lacks.
    """
    from .errors import CommandBlocked, PermissionRequired

    verdict = classify(command, extra_rules)
    if verdict.is_blocked:
        raise CommandBlocked(
            f"refused: {verdict.reason}. This command is on the never-run list and no "
            f"confirmation overrides it. If it is genuinely required, run it by hand in an "
            f"interactive session (uv run ac rdp / uv run ac shell)."
        )
    if verdict.needs_confirmation and not confirmed:
        raise PermissionRequired(
            f"confirmation required: {verdict.reason}. Ask the operator to approve, then "
            f"retry with confirmation."
        )
    return verdict
