"""Secret redaction, command policy, and credential handling.

These are the tests that matter most: a regression here leaks a production
password or lets a destructive command through unannounced.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from access_control import redact, safety
from access_control.audit import AuditLog
from access_control.credentials import Credential, CredentialStore, UnavailablePrompter
from access_control.errors import CommandBlocked, CredentialError, PermissionRequired
from access_control.transport.base import ExecResult

SECRET = "Tr0ub4dor&3-hunter2"


@pytest.fixture(autouse=True)
def clean_registry():
    redact.clear()
    yield
    redact.clear()


class TestRedaction:
    def test_registered_secret_is_masked(self) -> None:
        redact.register(SECRET)
        assert SECRET not in redact.redact(f"login failed for {SECRET} on host")
        assert redact.MASK in redact.redact(f"login failed for {SECRET}")

    def test_backslash_escaped_form_is_also_masked(self) -> None:
        secret = "pa\\ss\\word"
        redact.register(secret)
        assert secret.replace("\\", "\\\\") not in redact.redact(
            f"cmd {secret.replace(chr(92), chr(92) * 2)}"
        )

    def test_short_strings_are_not_registered(self) -> None:
        redact.register("ab")
        assert redact.redact("ab cd") == "ab cd"

    def test_longest_match_wins(self) -> None:
        redact.register("secret")
        redact.register("secretvalue")
        assert redact.redact("secretvalue") == redact.MASK

    def test_nested_structures_are_scrubbed(self) -> None:
        redact.register(SECRET)
        scrubbed = redact.redact_obj(
            {"cmd": f"connect {SECRET}", "list": [SECRET, {"k": SECRET}], "n": 5}
        )
        assert SECRET not in json.dumps(scrubbed)
        assert scrubbed["n"] == 5

    def test_clear_forgets_everything(self) -> None:
        redact.register(SECRET)
        redact.clear()
        assert redact.redact(SECRET) == SECRET

    def test_exec_result_scrubs_on_construction(self) -> None:
        redact.register(SECRET)
        result = ExecResult(
            node_id="n",
            channel="fake",
            command=f"net use /user:me {SECRET}",
            stdout=f"logged in with {SECRET}",
            stderr=f"failed: {SECRET}",
            ps_errors=[f"error near {SECRET}"],
        )
        blob = json.dumps(result.to_dict())
        assert SECRET not in blob
        assert blob.count(redact.MASK) >= 4

    def test_audit_records_never_contain_the_secret(self, tmp_path: Path) -> None:
        redact.register(SECRET)
        log = AuditLog(
            session_id="s1", agent_id="pytest", host_id="h", directory=tmp_path
        )
        log.emit("command", command=f"install --pass {SECRET}", nested={"pw": SECRET})
        log.close()
        written = log.path.read_text(encoding="utf-8")
        assert SECRET not in written
        assert redact.MASK in written

    def test_error_messages_are_scrubbed(self) -> None:
        redact.register(SECRET)
        error = redact.RedactingError(f"auth failed using {SECRET}")
        assert SECRET not in str(error)


class TestCommandPolicy:
    @pytest.mark.parametrize(
        "command",
        [
            "Format-Volume -DriveLetter D",
            "Clear-Disk -Number 1",
            "diskpart /s clean.txt ; select disk 0 ; clean",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda bs=1M",
            "rm -rf /var",
            "Disable-PSRemoting",
            "netsh advfirewall set allprofiles state off",
        ],
    )
    def test_catastrophic_commands_are_blocked(self, command: str) -> None:
        assert safety.classify(command).is_blocked
        with pytest.raises(CommandBlocked):
            safety.check(command, confirmed=True)

    def test_blocked_cannot_be_overridden_by_confirmation(self) -> None:
        with pytest.raises(CommandBlocked, match="no confirmation overrides"):
            safety.check("Format-Volume -DriveLetter X", confirmed=True)

    @pytest.mark.parametrize(
        "command",
        [
            "Restart-Computer -Force",
            "shutdown /r /t 0",
            "Stop-Service W3SVC",
            "systemctl restart nginx",
            "Remove-Item C:\\temp\\file.txt",
            "msiexec /x {GUID}",
            "wusa.exe patch.msu /quiet",
            "reg add HKLM\\Software\\X /v Y /d Z",
            "apt-get install nginx",
        ],
    )
    def test_state_changing_commands_need_confirmation(self, command: str) -> None:
        assert safety.classify(command).needs_confirmation
        with pytest.raises(PermissionRequired):
            safety.check(command, confirmed=False)
        assert safety.check(command, confirmed=True).needs_confirmation

    @pytest.mark.parametrize(
        "command",
        [
            "rm /tmp/something",
            "rm -f /var/log/old.log",
            "sudo rm /etc/thing",
            "mv /etc/a /etc/b",
            "chmod 644 /etc/passwd",
            "chown root:root /etc/thing",
            "kill 1234",
            "pkill -f myapp",
            "truncate -s 0 /var/log/big.log",
        ],
    )
    def test_posix_file_and_process_changes_need_confirmation(self, command: str) -> None:
        """Found in live testing: `rm` ran ungated on AIX while Remove-Item was gated.

        The two must behave the same -- deleting a file on a production server is
        not a read-only operation just because the host runs Unix.
        """
        assert safety.classify(command).needs_confirmation, command
        with pytest.raises(PermissionRequired):
            safety.check(command, confirmed=False)

    @pytest.mark.parametrize(
        "command",
        [
            "Get-Service W3SVC",
            "Get-ChildItem 'D:\\packages'",
            "Test-Path C:\\Windows",
            "uname -a; hostname",
            "df -h",
            "df -k | head -20",
            "$env:COMPUTERNAME",
            "hostname; uptime; id",
            "tail -n 200 /var/log/messages",
            "echo confirm",
            "grep alarm /var/log/app.log",
            "ls -l /home",
        ],
    )
    def test_read_only_commands_are_allowed(self, command: str) -> None:
        assert safety.classify(command).level == safety.ALLOWED, command
        safety.check(command)

    def test_rm_inside_a_word_is_not_matched(self) -> None:
        """`\\brm\\b` must not fire on 'confirm', 'alarm', or a path segment."""
        for command in ("echo confirm", "grep alarm x.log", "cat /var/farm/data"):
            assert safety.classify(command).level == safety.ALLOWED, command

    def test_a_comment_mentioning_reboot_is_not_an_instruction(self) -> None:
        """The exact false positive found while building: prose about exit codes.

        `# 3010 = installed and needs a reboot` describes a return value; it does
        not reboot anything, and gating on it would train operators to confirm
        blindly.
        """
        script = (
            "$p = Start-Process wusa.exe -Wait -PassThru\n"
            "# 0 = installed, 3010 = installed and needs a reboot\n"
            'if ($p.ExitCode -eq 0) { "done" }'
        )
        verdict = safety.classify(script)
        # wusa is still gated, but not for the reason in the comment.
        assert "reboot" not in (verdict.reason or "")

    def test_a_real_reboot_command_is_still_caught(self) -> None:
        assert safety.classify("apt-get update && reboot").needs_confirmation
        assert safety.classify("reboot").needs_confirmation

    def test_comment_only_script_is_allowed(self) -> None:
        assert safety.classify("# Restart-Computer would go here").level == safety.ALLOWED

    def test_empty_command_is_allowed(self) -> None:
        assert safety.classify("").level == safety.ALLOWED
        assert safety.classify("   \n ").level == safety.ALLOWED


class TestCredentials:
    def test_nothing_is_stored_on_disk(self, tmp_path: Path) -> None:
        store = CredentialStore(prompter=_ScriptedPrompter(["s3cret"]))
        store.acquire("bastion1", label="Bastion", username="u")
        assert not list(tmp_path.rglob("*s3cret*"))

    def test_secret_is_registered_for_redaction_immediately(self) -> None:
        store = CredentialStore(prompter=_ScriptedPrompter([SECRET]))
        store.acquire("n1", label="Node", username="u")
        assert redact.redact(f"using {SECRET}") == f"using {redact.MASK}"

    def test_repr_never_shows_the_password(self) -> None:
        cred = Credential(node_id="n", username="u", password=SECRET)
        assert SECRET not in repr(cred)
        assert "password=set" in repr(cred)

    def test_cached_credential_is_reused_without_reprompting(self) -> None:
        prompter = _ScriptedPrompter(["first"])
        store = CredentialStore(prompter=prompter)
        store.acquire("n1", label="Node")
        store.acquire("n1", label="Node")
        assert prompter.calls == 1

    def test_each_node_is_prompted_separately(self) -> None:
        """PLAN.md: a password is entered at every stage, not shared between them."""
        prompter = _ScriptedPrompter(["bastion-pw", "jump-pw", "target-pw"])
        store = CredentialStore(prompter=prompter)
        for node in ("bastion1", "jump1", "target1"):
            store.acquire(node, label=node)
        assert prompter.calls == 3
        assert store.peek("bastion1").password == "bastion-pw"
        assert store.peek("target1").password == "target-pw"

    def test_clear_wipes_and_unregisters(self) -> None:
        store = CredentialStore(prompter=_ScriptedPrompter([SECRET]))
        store.acquire("n1", label="Node")
        store.clear()
        assert store.known() == []
        assert redact.redact(SECRET) == SECRET

    def test_discard_after_auth_drops_the_plaintext(self) -> None:
        store = CredentialStore(prompter=_ScriptedPrompter([SECRET]), discard_after_auth=True)
        store.acquire("n1", label="Node")
        store.note_authenticated("n1")
        assert store.peek("n1").password is None

    def test_challenge_reuses_a_known_password_for_a_password_prompt(self) -> None:
        prompter = _ScriptedPrompter(["known"])
        store = CredentialStore(prompter=prompter)
        store.acquire("n1", label="Node")
        answers = store.answer_challenge("n1", "Node", [("Password: ", False)])
        assert answers == ["known"]
        assert prompter.calls == 1

    def test_challenge_asks_the_operator_for_an_otp(self) -> None:
        """An MFA prompt must reach a human -- it cannot be answered from cache."""
        prompter = _ScriptedPrompter(["password", "123456"])
        store = CredentialStore(prompter=prompter)
        store.acquire("n1", label="Node")
        answers = store.answer_challenge("n1", "Node", [("Verification code: ", False)])
        assert answers == ["123456"]

    def test_unavailable_prompter_explains_how_to_proceed(self) -> None:
        store = CredentialStore(prompter=UnavailablePrompter("no terminal"))
        with pytest.raises(CredentialError, match="ac connect"):
            store.acquire("n1", label="Node")

    def test_env_credentials_are_off_unless_opted_in(self, monkeypatch) -> None:
        monkeypatch.setenv("AC_PASSWORD_N1", "from-env")
        monkeypatch.delenv("AC_ALLOW_ENV_CREDENTIALS", raising=False)
        store = CredentialStore(prompter=_ScriptedPrompter(["typed"]))
        assert store.acquire("n1", label="Node").password == "typed"

    def test_env_credentials_work_when_explicitly_enabled(self, monkeypatch) -> None:
        monkeypatch.setenv("AC_ALLOW_ENV_CREDENTIALS", "1")
        monkeypatch.setenv("AC_PASSWORD_N1", "from-env")
        store = CredentialStore(prompter=UnavailablePrompter("no terminal"))
        assert store.acquire("n1", label="Node").password == "from-env"


class _ScriptedPrompter:
    """A prompter that returns canned answers, counting how often it is used."""

    name = "scripted"

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.calls = 0
        self.labels: list[str] = []

    def _next(self, label: str) -> str:
        self.calls += 1
        self.labels.append(label)
        if not self.answers:
            raise AssertionError("prompter asked for more answers than the test scripted")
        return self.answers.pop(0)

    def ask_secret(self, title: str, prompt: str, username: str | None = None) -> str:
        return self._next(title)

    def ask_username(self, title: str, prompt: str, default: str | None = None) -> str:
        return self._next(title)

    def ask_challenge(self, title: str, prompts) -> list[str]:
        return [self._next(title) for _ in prompts]
