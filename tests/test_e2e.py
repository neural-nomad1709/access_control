"""End-to-end loops over real sockets.

PLAN.md asks for at least two complete cycles before the product is called
ready. These run the whole stack -- config, credential prompting, a real SSH
handshake with key-then-password multi-factor, a real ``direct-tcpip`` hop to a
second server, the engine, the audit trail, and the loopback session protocol --
against SSH servers started in-process.

  Loop 1  happy path: connect through the bastion, list operations, gate,
          approve, run, verify, report, disconnect.
  Loop 2  failure and recovery: a step fails, diagnostics are collected, the
          agent remediates, re-runs only the failed step, and succeeds.

What these cannot cover is the WinRM leg, which needs a real Windows host; that
part is verified against the live environment per docs/testing.md.
"""

from __future__ import annotations

import io
import textwrap
import threading
from pathlib import Path
from typing import Any, Callable

import paramiko
import pytest

from access_control.audit import (
    EV_HOP_CONNECTED,
    EV_OPERATION_END,
    EV_SESSION_CLOSE,
    EV_STEP_END,
    AuditLog,
)
from access_control.config import load_inventory, load_operations
from access_control.credentials import CredentialStore
from access_control.daemon import SessionClient, SessionDescriptor, SessionServer
from access_control.engine import Engine
from access_control.errors import ConnectionFailed, PermissionRequired, SessionError
from access_control.session import Session
from access_control.transport.ssh import connect_chain
from sshfake import AuthPolicy, CommandResult, FakeSSHServer

BASTION_PASSWORD = "bastion-secret-password"
TARGET_PASSWORD = "target-secret-password"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch) -> None:
    """Keep the test off the real known_hosts, log dir, and session dir."""
    monkeypatch.setenv("AC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AC_KNOWN_HOSTS", str(tmp_path / "known_hosts"))
    monkeypatch.setenv("AC_HOST_KEY_POLICY", "accept-new")
    monkeypatch.delenv("AC_ALLOW_ENV_CREDENTIALS", raising=False)


@pytest.fixture
def client_key(tmp_path: Path) -> Path:
    key = paramiko.RSAKey.generate(2048)
    path = tmp_path / "id_test"
    key.write_private_key_file(str(path))
    return path


class ScriptedPrompter:
    """Answers password prompts from a per-node map, recording every prompt.

    The recorded labels are the assertion that matters for PLAN.md's security
    requirement: a distinct prompt must appear for every hop.
    """

    name = "scripted"

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.prompts: list[str] = []

    def _answer(self, title: str) -> str:
        self.prompts.append(title)
        for fragment, value in self.answers.items():
            if fragment in title:
                return value
        raise AssertionError(f"no scripted answer for prompt: {title}")

    def ask_secret(self, title: str, prompt: str, username: str | None = None) -> str:
        return self._answer(title)

    def ask_username(self, title: str, prompt: str, default: str | None = None) -> str:
        return default or "opuser"

    def ask_challenge(self, title: str, prompts: Any) -> list[str]:
        return [self._answer(title) for _ in prompts]


def build_config(tmp_path: Path, bastion_port: int, target_port: int, key_file: Path) -> Path:
    directory = tmp_path / "config"
    directory.mkdir(exist_ok=True)
    (directory / "inventory.yaml").write_text(
        textwrap.dedent(
            f"""
            hops:
              bastion1:
                kind: ssh
                host: 127.0.0.1
                port: {bastion_port}
                user: opuser
                description: Test bastion
                auth:
                  method: key+password
                  key_file: {key_file.as_posix()}

            hosts:
              app01:
                kind: linux
                host: 127.0.0.1
                port: {target_port}
                path: [bastion1]
                user: opuser
                description: Test application server
                tags: [linux]
                auth:
                  method: password
            """
        ),
        encoding="utf-8",
    )
    (directory / "operations.yaml").write_text(
        textwrap.dedent(
            r"""
            operations:
              - id: check-app
                description: Confirm the application service is healthy
                host_ids: [app01]
                requires_permission: false
                shell: bash
                steps:
                  - id: identify
                    desc: Identify the host
                    shell: bash
                    run: |
                      hostname
                    expect:
                      stdout_contains: app01

                  - id: service-state
                    desc: Confirm the service is running
                    shell: bash
                    run: |
                      systemctl is-active myapp
                    expect:
                      stdout_contains: active
                    on_failure:
                      collect:
                        - files: ['/var/log/myapp/error.log']
                      hints:
                        "3": >-
                          The service is stopped. Check the collected error log,
                          fix the cause, then start it and re-run this step.
                        "*": Unexpected state -- read the collected log.

              - id: install-app
                description: Install a package from the server-local share
                host_ids: [app01]
                requires_permission: true
                shell: bash
                params:
                  - name: package
                    required: true
                steps:
                  - id: install
                    desc: Install the package
                    shell: bash
                    destructive: true
                    run: |
                      apt-get install -y {{package}}
                    expect:
                      stdout_contains: '{{package}}'
            """
        ),
        encoding="utf-8",
    )
    return directory


def make_session(
    config: Path,
    prompter: ScriptedPrompter,
    tmp_path: Path,
    *,
    allowed: tuple[str, ...] = (),
    fallback_to_hop: bool = False,
    sink=None,
) -> Session:
    inventory = load_inventory(config / "inventory.yaml")
    catalog = load_operations(config / "operations.yaml")
    session_id = "20260101T120000Z-e2e"
    return Session(
        inventory=inventory,
        catalog=catalog,
        host_id="app01",
        agent_id="pytest-e2e",
        session_id=session_id,
        creds=CredentialStore(prompter=prompter),
        audit=AuditLog(
            session_id=session_id,
            agent_id="pytest-e2e",
            host_id="app01",
            directory=tmp_path / "audit",
            sink=sink,
        ),
        allowed_operations=allowed,
        # Off by default here so a test that expects a failure sees the
        # exception rather than a session quietly held at the bastion.
        fallback_to_hop=fallback_to_hop,
    )


# --------------------------------------------------------------------------
# The two servers used by both loops
# --------------------------------------------------------------------------


class AppServerState:
    """Mutable state so a test can 'fix' the host between runs."""

    def __init__(self) -> None:
        self.service_running = True
        self.installed: list[str] = []

    def respond(self, command: str) -> CommandResult:
        if "hostname" in command:
            return CommandResult(stdout="app01.internal\n")
        if "systemctl is-active" in command:
            if self.service_running:
                return CommandResult(stdout="active\n")
            # systemctl exits 3 for an inactive unit.
            return CommandResult(stdout="inactive\n", exit_status=3)
        if "systemctl start" in command:
            self.service_running = True
            return CommandResult(stdout="")
        if "tail -n" in command and "error.log" in command:
            return CommandResult(
                stdout="2026-01-01 12:00:00 FATAL myapp: config file /etc/myapp.conf not found\n"
            )
        if "apt-get install" in command:
            package = command.split()[-1]
            self.installed.append(package)
            return CommandResult(stdout=f"Setting up {package} ...\n")
        return CommandResult(stdout="")


@pytest.fixture
def environment(tmp_path: Path, client_key: Path):
    """A bastion and an application server, wired exactly like production."""
    state = AppServerState()
    bastion = FakeSSHServer(
        "bastion",
        policy=AuthPolicy(
            username="opuser",
            password=BASTION_PASSWORD,
            require_key_then_password=True,
        ),
        responder=lambda cmd: CommandResult(stdout="bastion\n"),
    )
    target = FakeSSHServer(
        "app01",
        policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD),
        responder=state.respond,
    )
    with bastion, target:
        config = build_config(tmp_path, bastion.port, target.port, client_key)
        yield config, bastion, target, state


# --------------------------------------------------------------------------
# Loop 1: the happy path
# --------------------------------------------------------------------------


class TestLoopOneHappyPath:
    def test_full_cycle(self, environment, tmp_path: Path) -> None:
        config, bastion, target, state = environment
        prompter = ScriptedPrompter(
            {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
        )
        session = make_session(config, prompter, tmp_path)

        # --- 1. connect: a password is prompted for at every hop -----------
        session.connect()
        assert session.active
        assert len(prompter.prompts) == 2, prompter.prompts
        assert any("Test bastion" in p for p in prompter.prompts)
        assert any("Test application server" in p for p in prompter.prompts)
        # The prompts must be distinguishable, or an operator types the wrong one.
        assert prompter.prompts[0] != prompter.prompts[1]

        # PLAN.md: "we access bastion through key + password". The server
        # accepted the key, asked for another factor, and got the password --
        # the OpenSSH `AuthenticationMethods publickey,password` chain.
        assert bastion.policy.attempts == ["publickey", "password"], bastion.policy.attempts
        assert target.policy.attempts == ["password"]

        # The bastion really did forward a connection onward.
        assert bastion.forwards, "the second hop should have gone through the bastion"
        assert bastion.forwards[0][1] == target.port

        # --- 2. the agent lists the configurable operations ---------------
        operations = {op["id"] for op in session.operations()}
        assert operations == {"check-app", "install-app"}

        engine = Engine(session)

        # --- 3. the gate holds until the operator approves -----------------
        with pytest.raises(PermissionRequired) as refusal:
            engine.run_operation("install-app", {"package": "myapp"})
        assert "apt-get install -y myapp" in str(refusal.value)
        assert state.installed == [], "nothing may run before approval"

        # --- 4. approved, it runs -----------------------------------------
        outcome = engine.run_operation("install-app", {"package": "myapp"}, confirmed=True)
        assert outcome.ok, outcome.to_dict()
        assert state.installed == ["myapp"]

        # --- 5. verification operation ------------------------------------
        check = engine.run_operation("check-app")
        assert check.ok
        assert [s.step_id for s in check.steps] == ["identify", "service-state"]

        # --- 6. status is reported before the path disappears -------------
        status = session.status()
        assert status["connected"] is True
        assert status["steps_ok"] >= 3

        report = session.close(status="closed")
        assert report["closed"] is True
        assert session.creds.known() == [], "credentials must be wiped on close"

        # --- 7. the audit trail reconstructs the whole run ----------------
        assert session.audit is not None
        records = session.audit.records

        # Canonical action records: source -> target for every connection.
        connects = [r for r in records if r.get("action") == "SSH_CONNECT"]
        assert [(r["source"], r["target"]) for r in connects] == [
            ("local", "bastion1"),
            ("bastion1", "app01"),
        ]
        assert all(r["result"] == "SUCCESS" for r in connects)

        steps = [r["step_id"] for r in session.audit.by_event(EV_STEP_END)]
        assert steps == ["install", "identify", "service-state"]
        assert all(r["agentId"] == "pytest-e2e" for r in records)
        assert all(r["sessionId"] == session.session_id for r in records)
        assert all(r["timestamp"] for r in records)
        assert session.audit.by_event(EV_SESSION_CLOSE)

        # The execution timeline reconstructs the whole run for someone
        # investigating after the fact -- connections, executions, and the close.
        timeline = session.audit.render_timeline()
        assert "SSH_CONNECT" in timeline
        assert "local -> bastion1" in timeline
        assert "bastion1 -> app01" in timeline
        assert "SCRIPT_EXECUTE" in timeline
        assert "SESSION_START" in timeline

        actions = [r["action"] for r in records if r.get("action")]
        assert actions[0] == "SESSION_START"
        assert "SCRIPT_EXECUTE" in actions
        assert "PERMISSION_REQUEST" in actions, "the refusal must be recorded too"

        # Written to disk, and no password anywhere in it.
        trail = session.audit.path.read_text(encoding="utf-8")
        assert BASTION_PASSWORD not in trail
        assert TARGET_PASSWORD not in trail
        assert session.audit.path.with_suffix(".md").exists()


# --------------------------------------------------------------------------
# Loop 2: failure, diagnosis, remediation, retry
# --------------------------------------------------------------------------


class TestLoopTwoFailureAndRecovery:
    def test_full_cycle(self, environment, tmp_path: Path) -> None:
        """The loop the whole design exists for: a step fails and gets fixed."""
        config, _bastion, _target, state = environment
        state.service_running = False  # the fault the agent has to find

        prompter = ScriptedPrompter(
            {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
        )
        session = make_session(config, prompter, tmp_path)
        session.connect()
        engine = Engine(session)

        # --- 1. the operation fails, and stops where it failed ------------
        first = engine.run_operation("check-app")
        assert not first.ok
        assert first.stopped_at == "service-state"
        assert [s.step_id for s in first.steps] == ["identify", "service-state"]

        failed = first.failed_step
        assert failed is not None
        assert failed.result is not None and failed.result.exit_code == 3

        # --- 2. it hands back diagnosis, not just a failure ---------------
        assert failed.collected, "on_failure.collect should have gathered the log"
        assert "config file /etc/myapp.conf not found" in failed.collected[0]["content"]
        assert failed.hint is not None and "service is stopped" in failed.hint

        payload = first.to_dict()
        assert "collected_logs" in payload["steps"][1]
        assert "run_command" in payload["next_action"]

        # --- 3. the agent investigates and remediates ---------------------
        investigation = engine.run_command("ls -l /etc/myapp.conf")
        assert investigation.ok

        repair = engine.run_command("systemctl start myapp", confirmed=True)
        assert repair.ok
        assert state.service_running is True

        # An unconfirmed state-changing command must still be refused.
        with pytest.raises(PermissionRequired):
            engine.run_command("systemctl restart myapp")

        # --- 4. re-run only the failed step, not the whole operation ------
        retry = engine.run_operation("check-app", start_at="service-state")
        assert retry.ok
        assert [s.step_id for s in retry.steps] == ["service-state"]

        # --- 5. clean close with a truthful report ------------------------
        report = session.close(status="closed")
        assert report["steps_failed"] >= 1, "the failure stays in the record"
        assert report["steps_ok"] >= 2
        assert session.creds.known() == []

        assert session.audit is not None
        ends = session.audit.by_event(EV_OPERATION_END)
        assert [e["status"] for e in ends] == ["failed", "ok"]


# --------------------------------------------------------------------------
# The same stack, driven the way an agent drives it
# --------------------------------------------------------------------------


class TestAgentPath:
    def test_agent_drives_a_session_over_the_socket(self, environment, tmp_path: Path) -> None:
        """What actually happens in production: the operator connects, the agent works.

        The agent side never sees a credential -- it only has a host id and a
        token, and the passwords stay in the session process.
        """
        config, _bastion, _target, state = environment
        prompter = ScriptedPrompter(
            {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
        )
        session = make_session(config, prompter, tmp_path).connect()

        server = SessionServer(session)
        ready = threading.Event()
        holder: dict[str, SessionDescriptor] = {}

        def on_ready(descriptor: SessionDescriptor) -> None:
            holder["d"] = descriptor
            ready.set()

        server.on_ready = on_ready
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        assert ready.wait(timeout=10)

        try:
            client = SessionClient(holder["d"], timeout=30)

            # The agent discovers what it may do.
            assert {op["id"] for op in client.call("operations")} == {"check-app", "install-app"}

            # It previews before asking for approval.
            preview = client.call("preview", operation_id="install-app", params={"package": "nginx"})
            assert "apt-get install -y nginx" in preview["steps"][0]["command"]

            # Without approval, nothing runs.
            with pytest.raises(Exception, match="approval"):
                client.call("run_operation", operation_id="install-app", params={"package": "nginx"})
            assert state.installed == []

            # With approval, it runs.
            result = client.call(
                "run_operation",
                operation_id="install-app",
                params={"package": "nginx"},
                confirmed=True,
            )
            assert result["ok"] is True
            assert state.installed == ["nginx"]

            # And it can read a log without a whole operation.
            log = client.call("fetch_log", path="/var/log/myapp/error.log", tail=20)
            assert "myapp" in log["stdout"]

            final = client.call("close")
            assert final["host_id"] == "app01"
        finally:
            server.shutdown("closed")
            thread.join(timeout=5)


# --------------------------------------------------------------------------
# Failure modes of the chain itself
# --------------------------------------------------------------------------


class TestChainFailures:
    def test_wrong_bastion_password_does_not_retain_the_credential(
        self, environment, tmp_path: Path
    ) -> None:
        config, _bastion, _target, _state = environment
        prompter = ScriptedPrompter(
            {"Test bastion": "wrong-password", "Test application server": TARGET_PASSWORD}
        )
        session = make_session(config, prompter, tmp_path)
        with pytest.raises(ConnectionFailed, match="authentication failed"):
            session.connect()
        assert session.creds.known() == [], "a rejected password must not be kept"

    def test_unreachable_bastion_names_the_address(self, tmp_path: Path, client_key: Path) -> None:
        config = build_config(tmp_path, 9, 9, client_key)  # port 9 = discard, nothing listens
        session = make_session(config, ScriptedPrompter({}), tmp_path)
        with pytest.raises(ConnectionFailed, match="127.0.0.1:9"):
            session.connect()

    def test_forwarding_capability_is_detected_when_permitted(
        self, environment, tmp_path: Path
    ) -> None:
        """The decisive question for any higher environment, asked directly.

        A bastion with `AllowTcpForwarding no` makes every jump impossible, and
        the failure otherwise looks like an unreachable target -- sending people
        to argue with a firewall team about a rule that is fine.
        """
        from access_control.transport.tunnel import forwarding_permitted

        config, _bastion, _target, _state = environment
        prompter = ScriptedPrompter(
            {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
        )
        session = make_session(config, prompter, tmp_path).connect()
        try:
            permitted, explanation = forwarding_permitted(session.ssh_hops[0])
            assert permitted is True
            assert "permitted" in explanation
        finally:
            session.close()

    def test_a_rejected_key_is_not_reported_as_a_bad_password(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        """The misdiagnosis that costs the most time.

        With `AuthenticationMethods publickey,password` the server needs BOTH.
        If the key is refused -- usually because the username is not the account
        it is enrolled against -- no password can ever succeed. Reporting only
        "password authentication failed" sends the operator retyping a
        credential that was never wrong.
        """
        from access_control.errors import ConnectionFailed

        bastion = FakeSSHServer(
            "bastion",
            policy=AuthPolicy(
                username="opuser",              # the account the key belongs to
                password=BASTION_PASSWORD,
                require_key_then_password=True,
            ),
        )
        target = FakeSSHServer("app01", policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD))
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            # Same server, same correct password -- but logging in as a
            # domain-qualified name the key is not enrolled for.
            inventory_path = config / "inventory.yaml"
            inventory_path.write_text(
                textwrap.dedent(
                    f"""
                    hops:
                      bastion1:
                        kind: ssh
                        host: 127.0.0.1
                        port: {bastion.port}
                        user: opuser
                        domain: PROD
                        description: Test bastion
                        auth:
                          method: key+password
                          key_file: {client_key.as_posix()}
                    hosts:
                      app01:
                        kind: linux
                        host: 127.0.0.1
                        port: {target.port}
                        path: [bastion1]
                        user: opuser
                        description: Test application server
                        auth:
                          method: password
                    """
                ),
                encoding="utf-8",
            )
            inventory = load_inventory(inventory_path)
            assert inventory.hop("bastion1").qualified_user == "PROD\\opuser"

            creds = CredentialStore(prompter=ScriptedPrompter({"Test bastion": BASTION_PASSWORD}))
            with pytest.raises(ConnectionFailed) as failure:
                connect_chain([inventory.hop("bastion1")], creds)

            message = str(failure.value)
            assert "ALREADY REJECTED" in message
            assert "PROD\\opuser" in message
            assert "password is probably not the problem" in message
            # And the server confirms the key really was refused first.
            assert bastion.policy.attempts[0] == "publickey"

    def test_a_refused_forward_records_why_not_just_a_reset(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        """A client of a local forward only ever sees ECONNRESET.

        The reason the bastion gave lives in `tunnel.errors` and nowhere else,
        so it has to be captured there or the failure is undiagnosable.
        """
        import socket as _socket
        import time

        from access_control.transport.tunnel import LocalTunnel

        bastion = FakeSSHServer(
            "locked-bastion",
            policy=AuthPolicy(username="opuser", password=BASTION_PASSWORD),
            allow_forward=False,
        )
        target = FakeSSHServer("app01", policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD))
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            inventory = load_inventory(config / "inventory.yaml")
            creds = CredentialStore(prompter=ScriptedPrompter({"Test bastion": BASTION_PASSWORD}))
            hops = connect_chain([inventory.hop("bastion1")], creds)
            tunnel = LocalTunnel(hops[0], "10.0.0.102", 5985)
            try:
                port = tunnel.start()
                client = _socket.create_connection(("127.0.0.1", port), timeout=5)
                try:
                    # Provoke the forward; the far side never opens.
                    client.sendall(b"GET / HTTP/1.1\r\n\r\n")
                    client.recv(1024)
                except OSError:
                    pass  # the reset the operator would see
                finally:
                    client.close()
                deadline = time.time() + 5
                while not tunnel.errors and time.time() < deadline:
                    time.sleep(0.05)
                assert tunnel.errors, "the refusal reason was thrown away"
            finally:
                tunnel.stop()
                hops[0].close()

    def test_forwarding_capability_is_detected_when_refused(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        """`AllowTcpForwarding no` must be named, not guessed at."""
        from access_control.transport.tunnel import forwarding_permitted

        bastion = FakeSSHServer(
            "locked-bastion",
            policy=AuthPolicy(username="opuser", password=BASTION_PASSWORD),
            allow_forward=False,
        )
        target = FakeSSHServer("app01", policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD))
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            inventory = load_inventory(config / "inventory.yaml")
            creds = CredentialStore(prompter=ScriptedPrompter({"Test bastion": BASTION_PASSWORD}))
            hops = connect_chain([inventory.hop("bastion1")], creds)
            try:
                permitted, explanation = forwarding_permitted(hops[0])
                assert permitted is False
                assert "AllowTcpForwarding no" in explanation
                assert "no client-side workaround" in explanation
            finally:
                hops[0].close()

    def test_probe_reports_blocked_forwarding_as_the_blocker(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        from access_control.probe import probe_route

        bastion = FakeSSHServer(
            "locked-bastion",
            policy=AuthPolicy(username="opuser", password=BASTION_PASSWORD),
            allow_forward=False,
        )
        target = FakeSSHServer("app01", policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD))
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            inventory = load_inventory(config / "inventory.yaml")
            creds = CredentialStore(prompter=ScriptedPrompter({"Test bastion": BASTION_PASSWORD}))
            report = probe_route(inventory, "app01", creds)

        assert report["forwarding_blocked_at"] == "bastion1"
        entry = report["nodes"][0]
        assert entry["verdict"] == "forwarding-blocked"
        assert entry["forwarding_permitted"] is False

    def test_a_bastion_refusing_forwards_is_reported_clearly(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        bastion = FakeSSHServer(
            "locked-bastion",
            policy=AuthPolicy(username="opuser", password=BASTION_PASSWORD),
            allow_forward=False,
        )
        target = FakeSSHServer("app01", policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD))
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            prompter = ScriptedPrompter(
                {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
            )
            session = make_session(config, prompter, tmp_path)
            with pytest.raises(ConnectionFailed, match="forbid forwarding|cannot open a forward"):
                session.connect()

    def test_a_failed_target_leg_holds_the_session_at_the_bastion(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        """The bastion password is already typed; a dead target must not waste it.

        Found the hard way against a live CVT bastion: the target leg failed,
        `ac connect` tore the whole chain down, and the only way to look at the
        bastion that had just authenticated was to connect again and retype
        every password. The chain stays up instead, held at the last hop.
        """
        bastion = FakeSSHServer(
            "locked-bastion",
            policy=AuthPolicy(username="opuser", password=BASTION_PASSWORD),
            allow_forward=False,
        )
        target = FakeSSHServer("app01", policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD))
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            prompter = ScriptedPrompter(
                {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
            )
            session = make_session(config, prompter, tmp_path, fallback_to_hop=True)
            session.connect()
            try:
                assert session.degraded
                assert session.current_node.id == "bastion1"
                assert session.active
                # The reason survives, so the prompt can explain itself.
                assert "forward" in (session.degraded_reason or "")

                # A caller aimed at the target is refused rather than silently
                # running on the bastion.
                with pytest.raises(SessionError, match="held at 'bastion1'"):
                    session.exec("hostname")
                assert session.operations() == []

                # The prompt's own commands do run, on the bastion.
                assert session.exec("hostname", allow_degraded=True).exit_code == 0
            finally:
                session.close()

    def test_probe_reports_a_reachable_bastion_even_when_auth_does_not_complete(
        self, environment, tmp_path: Path
    ) -> None:
        """Found against the live bastion: the hop row was dropped on auth failure.

        Proving TCP works is a useful result on its own. Losing it because the
        password prompt was declined reports "nothing was found" when the network
        plainly worked, and sends the operator chasing a firewall that is fine.
        """
        from access_control.credentials import UnavailablePrompter
        from access_control.probe import probe_route

        config, bastion, _target, _state = environment
        inventory = load_inventory(config / "inventory.yaml")
        creds = CredentialStore(prompter=UnavailablePrompter("no terminal"))

        report = probe_route(inventory, "app01", creds)

        assert report["nodes"], "the bastion row must survive an auth failure"
        entry = report["nodes"][0]
        assert entry["id"] == "bastion1"
        assert entry["ports"]["ssh"] is True, "TCP reachability was proven"
        assert entry["verdict"] == "reachable-not-authenticated"
        assert entry["authenticated"] is False
        assert report["blocked_at"] == "bastion1"
        assert "ac connect" in entry["advice"]

    def test_probe_reports_an_unreachable_bastion_distinctly(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        from access_control.probe import probe_route

        config = build_config(tmp_path, 9, 9, client_key)  # nothing listens on 9
        inventory = load_inventory(config / "inventory.yaml")
        report = probe_route(inventory, "app01", CredentialStore(prompter=ScriptedPrompter({})))

        entry = report["nodes"][0]
        assert entry["ports"]["ssh"] is False
        assert entry["verdict"] == "unreachable"
        assert "VPN" in entry["advice"]

    def test_changed_host_key_is_fatal(self, environment, tmp_path: Path, monkeypatch) -> None:
        """A key that changes mid-life is the interception case; it must never proceed."""
        config, bastion, _target, _state = environment
        # A real, valid key -- just not the one this server will present.
        impostor = paramiko.RSAKey.generate(2048)
        known_hosts = Path(tmp_path / "known_hosts")
        known_hosts.write_text(
            f"[127.0.0.1]:{bastion.port} {impostor.get_name()} {impostor.get_base64()}\n",
            encoding="utf-8",
        )
        prompter = ScriptedPrompter({"Test bastion": BASTION_PASSWORD})
        session = make_session(config, prompter, tmp_path)
        with pytest.raises(ConnectionFailed, match="HOST KEY MISMATCH"):
            session.connect()


# --------------------------------------------------------------------------
# The prompt the operator drives the session from
# --------------------------------------------------------------------------


class TestOperatorPrompt:
    """`ac connect` is a prompt, not a window that only blocks on a socket."""

    @staticmethod
    def _consoles():
        from rich.console import Console

        out, errs = io.StringIO(), io.StringIO()
        return Console(file=out, width=100, no_color=True), Console(file=errs, width=100, no_color=True), out, errs

    @staticmethod
    def _shell_target():
        """A target that answers `pwd` honestly, so `cd` can be verified."""
        cwd = {"path": "/home/opuser"}

        def respond(command: str) -> CommandResult:
            if command.startswith("cd ") and command.endswith("&& pwd"):
                # `cd '<path>' && cd <arg> && pwd` or `cd <arg> && pwd`
                target = command[: -len("&& pwd")].rsplit("cd ", 1)[1].strip().strip("'")
                if target == "/nowhere":
                    return CommandResult(stderr="no such directory\n", exit_status=1)
                cwd["path"] = target
                return CommandResult(stdout=f"{target}\n")
            if "pwd" in command:
                return CommandResult(stdout=f"{cwd['path']}\n")
            if "hostname" in command:
                return CommandResult(stdout="app01.internal\n")
            if "false" in command:
                return CommandResult(stderr="it failed\n", exit_status=7)
            return CommandResult(stdout="")

        bastion = FakeSSHServer(
            "bastion",
            policy=AuthPolicy(
                username="opuser", password=BASTION_PASSWORD, require_key_then_password=True
            ),
            responder=lambda cmd: CommandResult(stdout="bastion\n"),
        )
        target = FakeSSHServer(
            "app01", policy=AuthPolicy(username="opuser", password=TARGET_PASSWORD), responder=respond
        )
        return bastion, target

    def test_the_prompt_names_the_machine_and_carries_cd(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        from access_control.operator_shell import OperatorShell, _prompt_markup

        bastion, target = self._shell_target()
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            prompter = ScriptedPrompter(
                {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
            )
            session = make_session(config, prompter, tmp_path)
            session.connect()
            try:
                console, errs, out, err_out = self._consoles()
                shell = OperatorShell(session, console, errs)

                # The prompt names the machine, always.
                assert "app01" in _prompt_markup(session)
                assert session.prompt_label in _prompt_markup(session)
                assert "FALLBACK" not in _prompt_markup(session)

                # `cd` sticks: each exec is its own channel, so the prompt has
                # to carry the directory itself or every path would be relative
                # to the login directory forever.
                shell._execute("cd /var/log")
                assert shell.cwd == "/var/log"
                shell._execute("pwd")
                assert "/var/log" in out.getvalue()

                # A failed `cd` leaves the old directory alone.
                shell._execute("cd /nowhere")
                assert shell.cwd == "/var/log"

                # A non-zero exit is reported rather than swallowed.
                shell._execute("false")
                assert "exit 7" in err_out.getvalue()
            finally:
                session.close()

    def test_the_prompt_refuses_the_never_run_list(
        self, tmp_path: Path, client_key: Path
    ) -> None:
        """A human at a keyboard may confirm a risky command, not a fatal one."""
        from access_control.operator_shell import OperatorShell

        bastion, target = self._shell_target()
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            prompter = ScriptedPrompter(
                {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
            )
            session = make_session(config, prompter, tmp_path)
            session.connect()
            try:
                console, errs, _out, err_out = self._consoles()
                OperatorShell(session, console, errs)._execute("rm -rf /")
                assert "blocked" in err_out.getvalue()
            finally:
                session.close()

    def test_exit_closes_the_loop(self, tmp_path: Path, client_key: Path) -> None:
        from access_control.operator_shell import OperatorShell

        bastion, target = self._shell_target()
        with bastion, target:
            config = build_config(tmp_path, bastion.port, target.port, client_key)
            prompter = ScriptedPrompter(
                {"Test bastion": BASTION_PASSWORD, "Test application server": TARGET_PASSWORD}
            )
            session = make_session(config, prompter, tmp_path)
            session.connect()
            try:
                console, errs, out, _err = self._consoles()
                script = iter(["", "hostname", ":where", ":exit"])
                console.input = lambda prompt="": next(script)  # type: ignore[method-assign]
                assert OperatorShell(session, console, errs).run() == "closed"
                printed = out.getvalue()
                assert "app01.internal" in printed
                assert "this is app01" in printed
            finally:
                session.close()
