"""Interactive credential collection.

PLAN.md is explicit: *"at each stage password will be prompted to user for user
entry in every case (like bastion, jump server and target server)"*.  Nothing is
stored -- no keyring, no file, no environment variable by default.  Secrets live
in this process's memory, are registered with :mod:`.redact` the moment they are
collected, and are wiped on disconnect.

The awkward part is *where* the prompt appears.  A tool invoked by an agent has
no controlling terminal, so ``getpass`` would read EOF and hang the run.  Two
prompters solve that:

``TerminalPrompter``
    Used when stdin is a real TTY -- i.e. the operator ran ``ac connect``
    themselves.  This is the preferred path.

``WindowsCredUIPrompter``
    Used when there is no TTY.  Raises a native Windows credential dialog on the
    operator's desktop, so the secret is typed into Windows, never into the
    agent's conversation.

A password must never be typed into a chat window: it would be recorded in the
conversation transcript.  Neither prompter can be driven by the agent.
"""

from __future__ import annotations

import getpass
import os
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

from .context import qualify_username
from .errors import CredentialError
from .redact import register, unregister

#: Opt-in escape hatch for automated testing only.  Never set this on a machine
#: with access to production: it lets credentials come from the environment,
#: which defeats the manual-entry requirement.
ENV_OPT_IN = "AC_ALLOW_ENV_CREDENTIALS"


def env_credentials_allowed() -> bool:
    return os.environ.get(ENV_OPT_IN, "").strip().lower() in ("1", "true", "yes")


def _env_key(node_id: str, suffix: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in node_id).upper()
    return f"AC_{suffix}_{safe}"


# --------------------------------------------------------------------------
# Credential value
# --------------------------------------------------------------------------


@dataclass
class Credential:
    """One node's credentials.  Plaintext, in memory, for this session only."""

    node_id: str
    username: str | None = None
    password: str | None = None
    key_file: Path | None = None
    key_passphrase: str | None = None
    #: The domain this identity belongs to, recorded so the audit trail shows
    #: which directory an authentication was made against.
    domain: str = ""

    def wipe(self) -> None:
        """Forget the secrets and stop redacting them."""
        unregister(self.password)
        unregister(self.key_passphrase)
        self.password = None
        self.key_passphrase = None

    def __repr__(self) -> str:  # never leak via a traceback or debugger dump
        return (
            f"Credential(node_id={self.node_id!r}, username={self.username!r}, "
            f"password={'set' if self.password else 'unset'}, "
            f"key_file={self.key_file!r}, "
            f"key_passphrase={'set' if self.key_passphrase else 'unset'})"
        )


# --------------------------------------------------------------------------
# Prompters
# --------------------------------------------------------------------------


class Prompter(Protocol):
    """Something that can ask a human for a secret."""

    name: str

    def ask_secret(self, title: str, prompt: str, username: str | None = None) -> str: ...

    def ask_username(self, title: str, prompt: str, default: str | None = None) -> str: ...

    def ask_challenge(self, title: str, prompts: Sequence[tuple[str, bool]]) -> list[str]:
        """Answer a server-driven challenge (keyboard-interactive / MFA).

        ``prompts`` is a sequence of ``(text, echo)`` pairs exactly as the server
        sent them, so an OTP prompt reaches the operator verbatim.
        """
        ...


#: Environment markers set by agent harnesses that hand a child process a
#: tty-shaped stdin nobody is typing at. ``isatty()`` returns True there, so a
#: password prompt blocks forever instead of failing -- the operator sees the
#: banner, no prompt, and a command that never returns. Treat these as "no
#: usable terminal" and let the desktop dialog take the credential instead.
#: ``AC_PROMPTER=terminal`` still forces the terminal, since it is checked first.
AGENT_HARNESS_VARS = ("CLAUDECODE", "AI_AGENT", "CLAUDE_CODE_ENTRYPOINT")


def _under_agent_harness() -> bool:
    return any(os.environ.get(var) for var in AGENT_HARNESS_VARS)


class TerminalPrompter:
    """Prompts on the controlling terminal.  Requires a real TTY."""

    name = "terminal"

    @staticmethod
    def available() -> bool:
        if _under_agent_harness():
            return False
        try:
            return bool(sys.stdin) and sys.stdin.isatty()
        except (AttributeError, ValueError):
            return False

    def _banner(self, title: str) -> None:
        print(f"\n== {title} ==", file=sys.stderr, flush=True)

    @staticmethod
    def _eof_fallback() -> "WindowsCredUIPrompter | None":
        """The dialog to use when the 'terminal' turns out not to be typeable.

        ``isatty()`` is not proof that anyone can answer: a terminal harness --
        an agent shell, a CI runner, an editor's run pane -- can hand us a tty
        whose stdin is already at EOF. That surfaces as an instant EOFError
        rather than a wait, and dying there strands the operator with no prompt
        and no explanation. If the desktop dialog is reachable, ask there
        instead. A KeyboardInterrupt is a real cancellation and never lands
        here.
        """
        return WindowsCredUIPrompter() if WindowsCredUIPrompter.available() else None

    def ask_secret(self, title: str, prompt: str, username: str | None = None) -> str:
        self._banner(title)
        if username:
            print(f"   user: {username}", file=sys.stderr, flush=True)
        try:
            value = getpass.getpass(f"   {prompt}: ")
        except EOFError as exc:
            dialog = self._eof_fallback()
            if dialog is None:
                raise CredentialError(
                    f"{title}: stdin is at EOF, so the password cannot be typed here, "
                    f"and no credential dialog is available.\n"
                    f"Run this from a real terminal window."
                ) from exc
            print(
                "   this window cannot take a password -- answer the Windows dialog "
                "on your desktop",
                file=sys.stderr,
                flush=True,
            )
            return dialog.ask_secret(title, prompt, username)
        except KeyboardInterrupt as exc:
            raise CredentialError(f"{title}: cancelled at the prompt") from exc
        if not value:
            raise CredentialError(f"{title}: empty value entered")
        return value

    def ask_username(self, title: str, prompt: str, default: str | None = None) -> str:
        self._banner(title)
        suffix = f" [{default}]" if default else ""
        try:
            value = input(f"   {prompt}{suffix}: ").strip()
        except EOFError as exc:
            dialog = self._eof_fallback()
            if dialog is None:
                raise CredentialError(f"{title}: cancelled at the prompt") from exc
            return dialog.ask_username(title, prompt, default)
        except KeyboardInterrupt as exc:
            raise CredentialError(f"{title}: cancelled at the prompt") from exc
        return value or (default or "")

    def ask_challenge(self, title: str, prompts: Sequence[tuple[str, bool]]) -> list[str]:
        self._banner(title)
        answers: list[str] = []
        for text, echo in prompts:
            label = text.strip() or "response"
            try:
                answers.append(input(f"   {label} ") if echo else getpass.getpass(f"   {label} "))
            except EOFError as exc:
                dialog = self._eof_fallback()
                if dialog is None:
                    raise CredentialError(f"{title}: cancelled at the prompt") from exc
                # Hand the whole remaining challenge to the dialog: a
                # keyboard-interactive exchange has to be answered by one party.
                return answers + dialog.ask_challenge(title, prompts[len(answers) :])
            except KeyboardInterrupt as exc:
                raise CredentialError(f"{title}: cancelled at the prompt") from exc
        return answers


class WindowsCredUIPrompter:
    """Raises the native Windows credential dialog on the operator's desktop.

    This is the path used when an agent triggers a connection: the dialog appears
    on the user's screen and the secret goes straight from Windows into this
    process, never through the agent.
    """

    name = "windows-dialog"

    # win32cred constants, spelled out so a pywin32 build missing one still works.
    _GENERIC = 0x00040000
    _DO_NOT_PERSIST = 0x00000002
    _ALWAYS_SHOW_UI = 0x00000080
    _KEEP_USERNAME = 0x00100000
    _EXCLUDE_CERTIFICATES = 0x00000008

    # CREDUI_MAX_CAPTION_LENGTH / CREDUI_MAX_MESSAGE_LENGTH from wincred.h.
    _MAX_CAPTION = 128
    _MAX_MESSAGE = 1024

    @staticmethod
    def available() -> bool:
        if sys.platform != "win32":
            return False
        if os.environ.get("AC_NO_GUI_PROMPT"):
            return False
        try:
            import win32cred  # noqa: F401
        except ImportError:
            return False
        return True

    def _prompt(
        self, title: str, message: str, username: str | None, keep_username: bool
    ) -> tuple[str, str]:
        import pywintypes
        import win32cred

        flags = (
            self._GENERIC
            | self._DO_NOT_PERSIST
            | self._ALWAYS_SHOW_UI
            | self._EXCLUDE_CERTIFICATES
        )
        if keep_username and username:
            flags |= self._KEEP_USERNAME

        # CredUI caps the caption at CREDUI_MAX_CAPTION_LENGTH (128) and the body
        # at CREDUI_MAX_MESSAGE_LENGTH (1024), and rejects the whole call with
        # ERROR_INVALID_PARAMETER (87) rather than truncating. A hop label
        # carries the node's inventory description, which runs past 128 easily,
        # so clamp instead of letting the dialog fail to open at all.
        caption = f"access-control: {title}"
        if len(caption) > self._MAX_CAPTION:
            caption = caption[: self._MAX_CAPTION - 3] + "..."
        if len(message) > self._MAX_MESSAGE:
            message = message[: self._MAX_MESSAGE - 3] + "..."

        try:
            result = win32cred.CredUIPromptForCredentials(
                TargetName=title,
                AuthError=0,
                UserName=username or "",
                Password="",
                Save=False,
                Flags=flags,
                UiInfo={"MessageText": message, "CaptionText": caption},
            )
        except TypeError:
            # Older pywin32 builds only accept positional arguments.
            result = win32cred.CredUIPromptForCredentials(
                title, 0, username or "", "", False, flags
            )
        except pywintypes.error as exc:
            # 1223 == ERROR_CANCELLED
            if getattr(exc, "winerror", None) == 1223:
                raise CredentialError(f"{title}: the credential dialog was cancelled") from exc
            raise CredentialError(f"{title}: credential dialog failed ({exc})") from exc

        got_user, got_password = str(result[0] or ""), str(result[1] or "")
        if not got_password:
            raise CredentialError(f"{title}: no password entered in the dialog")
        return got_user, got_password

    def ask_secret(self, title: str, prompt: str, username: str | None = None) -> str:
        _, password = self._prompt(title, prompt, username, keep_username=True)
        return password

    def ask_username(self, title: str, prompt: str, default: str | None = None) -> str:
        user, _ = self._prompt(title, prompt, default, keep_username=False)
        return user or (default or "")

    def ask_challenge(self, title: str, prompts: Sequence[tuple[str, bool]]) -> list[str]:
        answers: list[str] = []
        for text, _echo in prompts:
            answers.append(self.ask_secret(title, text.strip() or "response"))
        return answers


class UnavailablePrompter:
    """Used when nothing can reach a human.  Fails with actionable guidance."""

    name = "unavailable"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def _fail(self, title: str) -> None:
        raise CredentialError(
            f"{title}: no way to prompt for a credential ({self.reason}).\n"
            f"Passwords are never stored and must be typed by you, not by the agent.\n"
            f"Open a session yourself first:\n"
            f"    uv run ac connect <host>\n"
            f"then retry -- the agent will reuse that authenticated session."
        )

    def ask_secret(self, title: str, prompt: str, username: str | None = None) -> str:
        self._fail(title)
        raise AssertionError("unreachable")

    def ask_username(self, title: str, prompt: str, default: str | None = None) -> str:
        self._fail(title)
        raise AssertionError("unreachable")

    def ask_challenge(self, title: str, prompts: Sequence[tuple[str, bool]]) -> list[str]:
        self._fail(title)
        raise AssertionError("unreachable")


def select_prompter(force: str | None = None) -> Prompter:
    """Pick the best prompter for the current context.

    Terminal first (the operator ran the command), then the Windows dialog (an
    agent ran it while the operator is at the machine).
    """
    force = force or os.environ.get("AC_PROMPTER")
    if force == "terminal":
        return TerminalPrompter()
    if force in ("windows", "gui", "dialog"):
        return WindowsCredUIPrompter()
    if force == "none":
        return UnavailablePrompter("prompting disabled by AC_PROMPTER=none")

    if TerminalPrompter.available():
        return TerminalPrompter()
    if WindowsCredUIPrompter.available():
        return WindowsCredUIPrompter()
    return UnavailablePrompter("no interactive terminal and no Windows credential dialog")


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------


@dataclass
class CredentialStore:
    """In-memory credentials for one session, keyed by node id.

    Held only so a multi-step run does not re-prompt for every command.  Wiped by
    :meth:`clear`, which the session calls on disconnect.
    """

    prompter: Prompter = field(default_factory=select_prompter)
    #: Discard the plaintext as soon as authentication succeeds.  Off by default
    #: because sudo and post-reboot reconnects need it again mid-session.
    discard_after_auth: bool = False
    _creds: dict[str, Credential] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def known(self) -> list[str]:
        with self._lock:
            return sorted(self._creds)

    def has(self, node_id: str) -> bool:
        with self._lock:
            return node_id in self._creds

    def peek(self, node_id: str) -> Credential | None:
        with self._lock:
            return self._creds.get(node_id)

    def put(self, cred: Credential) -> Credential:
        register(cred.password)
        register(cred.key_passphrase)
        with self._lock:
            self._creds[cred.node_id] = cred
        return cred

    def acquire(
        self,
        node_id: str,
        *,
        label: str,
        username: str | None = None,
        need_password: bool = True,
        key_file: Path | None = None,
        need_key_passphrase: bool = False,
        prompt_username: bool = False,
        force: bool = False,
        domain: str | None = None,
    ) -> Credential:
        """Return this node's credential, prompting for whatever is missing.

        ``label`` is what the operator sees, e.g. ``"Bastion bastion1 [QA]
        (operator@bastion1.example.net:2222)"`` -- it must make it unambiguous which
        machine the password is for.

        ``domain`` qualifies a bare username as ``DOMAIN\\user``. Windows auth
        against a domain-joined host fails with an unqualified name, and the
        failure looks like a wrong password rather than a wrong identity.
        """
        with self._lock:
            existing = self._creds.get(node_id)
        if existing and not force:
            satisfied = (existing.password or not need_password) and (
                existing.key_passphrase or not need_key_passphrase
            )
            if satisfied:
                return existing

        cred = existing or Credential(node_id=node_id, username=username, key_file=key_file)
        cred.username = cred.username or username
        cred.key_file = cred.key_file or key_file
        cred.domain = cred.domain or (domain or "")

        if prompt_username and not cred.username:
            typed = self._username_from_env(node_id) or self.prompter.ask_username(
                label, f"username{f' (domain {domain})' if domain else ''}"
            )
            cred.username = qualify_username(typed, domain)

        if need_key_passphrase and not cred.key_passphrase:
            cred.key_passphrase = self._from_env(node_id, "KEY_PASSPHRASE") or (
                self.prompter.ask_secret(
                    label, f"passphrase for {key_file.name if key_file else 'key'}", cred.username
                )
            )

        if need_password and not cred.password:
            cred.password = self._from_env(node_id, "PASSWORD") or self.prompter.ask_secret(
                label, "password", cred.username
            )

        return self.put(cred)

    def answer_challenge(self, node_id: str, label: str, prompts: Sequence[tuple[str, bool]]) -> list[str]:
        """Answer a keyboard-interactive challenge, reusing a known password.

        A single hidden prompt that looks like a password question is answered
        from the stored credential; anything else (an OTP, a security question)
        goes to the operator verbatim.
        """
        if len(prompts) == 1:
            text, echo = prompts[0]
            if not echo and "password" in text.lower():
                cred = self.peek(node_id)
                if cred and cred.password:
                    return [cred.password]

        answers = self.prompter.ask_challenge(label, prompts)
        for answer, (_text, echo) in zip(answers, prompts):
            if not echo:
                register(answer)
        return answers

    def discard(self, node_id: str) -> None:
        with self._lock:
            cred = self._creds.pop(node_id, None)
        if cred:
            cred.wipe()

    def clear(self) -> None:
        """Wipe every credential.  Called on session disconnect."""
        with self._lock:
            creds = list(self._creds.values())
            self._creds.clear()
        for cred in creds:
            cred.wipe()

    def note_authenticated(self, node_id: str) -> None:
        """Hook for :attr:`discard_after_auth`: drop the plaintext once used."""
        if not self.discard_after_auth:
            return
        cred = self.peek(node_id)
        if cred:
            cred.wipe()

    # -- environment escape hatch (testing only) --------------------------

    @staticmethod
    def _from_env(node_id: str, suffix: str) -> str | None:
        if not env_credentials_allowed():
            return None
        value = os.environ.get(_env_key(node_id, suffix))
        if value:
            register(value)
        return value or None

    @staticmethod
    def _username_from_env(node_id: str) -> str | None:
        if not env_credentials_allowed():
            return None
        return os.environ.get(_env_key(node_id, "USERNAME")) or None
