"""The prompt an operator drives a live session from.

``ac connect`` used to open the path and then block on a socket, printing
"Connected. Leave this window open."  That window was authenticated, held every
password, and did nothing -- so an operator who wanted to look at the machine
opened a *second* connection and typed the passwords again.

This module gives that window a prompt.  It always names the machine the next
command will reach, because the whole point of a bastion chain is that "where am
I?" is not obvious, and a session that has fallen back to a hop looks exactly
like one that has not::

    appuser@10.0.0.29 [app-stg01-bastion] $
    operator@bastion-staging.example.net [bastion-staging · FALLBACK] $

Commands run through the same audited channel everything else uses, with the
same catastrophic-command deny-list applied.  This is not a replacement for
``ac shell``: that hands you the system ``ssh`` client and a real TTY, so it is
what you want for anything full-screen.  This is for the checks you run *while*
holding a session -- and, when the target leg failed, for diagnosing the hop.
"""

from __future__ import annotations

import shlex
from typing import Any

from rich.console import Console

from .errors import AccessControlError, CommandBlocked, PermissionRequired
from .redact import redact
from .safety import check as safety_check
from .session import Session

DEFAULT_TIMEOUT_S = 300

HELP = """\
Type a command and it runs on the machine named in the prompt.

  :help / ?        this text
  :status          session id, route, idle timer, audit file
  :where           which machine the prompt is on, and why
  :route           the full hop chain, verbatim from inventory.yaml
  :retry           re-attempt the target leg (only when held at a hop)
  :timeout <secs>  per-command timeout (default 300)
  :exit / :quit    close the session and wipe credentials

Ctrl-C abandons the line you are typing. Ctrl-D closes the session.
`cd` is remembered between commands on POSIX hosts; nothing else is -- each
command is its own channel, so shell variables and background jobs do not
survive.\
"""


def _prompt_markup(session: Session) -> str:
    """``user@address [node] $`` -- coloured, and loud when it is a fallback."""
    node = session.current_node
    where = f"[bold cyan]{session.prompt_label}[/bold cyan]"
    if session.degraded:
        tag = f"[bold yellow]\\[{node.id} · FALLBACK][/bold yellow]"
    else:
        tag = f"[dim]\\[{node.id}][/dim]"
    sigil = ">" if node.is_windows else "$"
    return f"{where} {tag} {sigil} "


class OperatorShell:
    """A read-eval-print loop over one live :class:`~.session.Session`."""

    def __init__(self, session: Session, console: Console, err: Console) -> None:
        self.session = session
        self.console = console
        self.err = err
        self.timeout_s = DEFAULT_TIMEOUT_S
        #: Working directory, carried between commands on POSIX hosts.  Each
        #: exec opens its own channel, so a bare `cd` would otherwise vanish.
        self.cwd: str | None = None

    # -- loop -------------------------------------------------------------

    def run(self) -> str:
        """Drive the session until the operator leaves.  Returns a close status."""
        self.console.print(
            "[dim]Type :help for the prompt's own commands, :exit to close the "
            "session.[/dim]"
        )
        while True:
            if not self.session.active:
                self.err.print(
                    "[yellow]the session is no longer active "
                    "(dropped, or idle past its timeout)[/yellow]"
                )
                return "disconnected"
            try:
                line = self.console.input(_prompt_markup(self.session))
            except KeyboardInterrupt:
                self.console.print("[dim]^C  (:exit closes the session)[/dim]")
                continue
            except EOFError:
                self.console.print()
                return "closed"

            line = line.strip()
            if not line:
                continue
            if line.startswith(":") or line in ("?", "help", "exit", "quit"):
                if self._meta(line.lstrip(":")):
                    return "closed"
                continue
            self._execute(line)

    # -- meta commands ----------------------------------------------------

    def _meta(self, line: str) -> bool:
        """Handle a ``:`` command.  Returns True when the session should close."""
        parts = shlex.split(line) if line else [""]
        name, args = parts[0].lower(), parts[1:]

        if name in ("exit", "quit", "q"):
            return True
        if name in ("help", "?", "h"):
            self.console.print(HELP)
        elif name == "status":
            self._show_status()
        elif name == "where":
            self._show_where()
        elif name == "route":
            self.console.print(self.session.route.describe_verbose())
        elif name == "retry":
            self._retry()
        elif name == "timeout":
            self._set_timeout(args)
        else:
            self.err.print(f"[yellow]unknown prompt command ':{name}' -- try :help[/yellow]")
        return False

    def _show_status(self) -> None:
        status: dict[str, Any] = self.session.status()
        for field in (
            "session_id",
            "host_id",
            "current_node",
            "route",
            "connected",
            "idle_s",
            "expires_in_s",
            "log_file",
        ):
            if status.get(field) is not None:
                self.console.print(f"  {field:<14} {status[field]}")

    def _show_where(self) -> None:
        node = self.session.current_node
        self.console.print(f"  machine   {node.id}  ({self.session.prompt_label})")
        if node.description:
            self.console.print(f"  described {node.description}")
        if self.session.degraded:
            self.console.print(
                f"  [yellow]This is a FALLBACK.[/yellow] The leg to "
                f"'{self.session.host_id}' failed:\n"
                f"    {redact(self.session.degraded_reason or '')}\n"
                f"  Fix the far end, then :retry -- the hops below stay authenticated, "
                f"so it costs no password."
            )
        else:
            self.console.print(f"  target    yes -- this is {self.session.host_id}")

    def _retry(self) -> None:
        if not self.session.degraded:
            self.console.print(
                f"[dim]already on {self.session.host_id}; nothing to retry[/dim]"
            )
            return
        self.console.print(f"Re-attempting the leg to {self.session.host_id} ...")
        if self.session.retry_target():
            self.console.print(f"[green]connected[/green] -- now on {self.session.host_id}")
            self.cwd = None
        else:
            self.err.print(
                f"[red]still unreachable:[/red] "
                f"{redact(self.session.degraded_reason or '')}"
            )

    def _set_timeout(self, args: list[str]) -> None:
        if not args:
            self.console.print(f"  timeout   {self.timeout_s}s")
            return
        try:
            value = int(args[0])
        except ValueError:
            self.err.print("[yellow]:timeout takes a number of seconds[/yellow]")
            return
        if value <= 0:
            self.err.print("[yellow]:timeout must be positive[/yellow]")
            return
        self.timeout_s = value
        self.console.print(f"  timeout   {self.timeout_s}s")

    # -- running a command ------------------------------------------------

    def _execute(self, line: str) -> None:
        try:
            # The prompt is a human at a keyboard, so a CONFIRM-level command is
            # theirs to make -- but the never-run list still holds.  It exists
            # for the commands nobody means to type.
            safety_check(line, confirmed=True)
        except CommandBlocked as exc:
            self.err.print(f"[bold red]blocked:[/bold red] {exc}")
            if self.session.audit:
                self.session.audit.action(
                    "COMMAND_BLOCKED",
                    source="operator-prompt",
                    target=self.session.current_node.id,
                    result="BLOCKED",
                    command=line,
                )
            return
        except PermissionRequired:  # pragma: no cover - confirmed=True precludes it
            pass

        if self._absorb_cd(line):
            return

        try:
            result = self.session.exec(
                self._with_cwd(line), timeout_s=self.timeout_s, allow_degraded=True
            )
        except AccessControlError as exc:
            self.err.print(f"[red]{exc}[/red]")
            return
        except KeyboardInterrupt:
            # The remote command keeps running; the channel is torn down when
            # the session closes.  Say so rather than implying it was killed.
            self.err.print(
                "[yellow]^C -- stopped waiting. The command may still be running "
                "on the remote host.[/yellow]"
            )
            return

        self._report(line, result)

    def _report(self, line: str, result: Any) -> None:
        if result.stdout:
            self.console.print(redact(result.stdout).rstrip("\n"), markup=False, highlight=False)
        if result.stderr:
            self.err.print(redact(result.stderr).rstrip("\n"), markup=False, highlight=False)
        if result.timed_out:
            self.err.print(
                f"[yellow]timed out after {self.timeout_s}s "
                f"(raise it with :timeout <secs>)[/yellow]"
            )
        elif result.exit_code:
            self.err.print(f"[yellow]exit {result.exit_code}[/yellow]")

        if self.session.audit:
            self.session.audit.action(
                "COMMAND",
                source="operator-prompt",
                target=self.session.current_node.id,
                result="SUCCESS" if result.exit_code == 0 else "FAILURE",
                command=line,
                exit_code=result.exit_code,
                degraded=self.session.degraded,
            )

    # -- working directory ------------------------------------------------

    def _with_cwd(self, line: str) -> str:
        if self.cwd is None or self.session.current_node.is_windows:
            return line
        return f"cd {shlex.quote(self.cwd)} && {line}"

    def _absorb_cd(self, line: str) -> bool:
        """Handle a bare ``cd``, remembering where it landed.

        Returns True when the line was a ``cd`` and has been dealt with.  Only
        POSIX hosts get this: a Windows target runs each command through PSRP,
        where the runspace already carries its own location.
        """
        if self.session.current_node.is_windows:
            return False
        stripped = line.strip()
        if stripped != "cd" and not stripped.startswith("cd "):
            return False
        # Ask the remote shell where that landed rather than resolving the path
        # here: `cd -`, `cd ~user` and symlinks are the shell's business.
        probe = f"{self._with_cwd(stripped)} && pwd"
        try:
            result = self.session.exec(probe, timeout_s=30, allow_degraded=True)
        except AccessControlError as exc:
            self.err.print(f"[red]{exc}[/red]")
            return True
        landed = redact(result.stdout).strip().splitlines()
        if result.exit_code == 0 and landed:
            self.cwd = landed[-1]
        else:
            self.err.print(redact(result.stderr).strip() or f"cd failed ({stripped})")
        return True


def run_operator_shell(session: Session, console: Console, err: Console) -> str:
    return OperatorShell(session, console, err).run()
