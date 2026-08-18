"""Session descriptors and the loopback protocol the agent talks over.

The server is exercised for real -- a socket is bound, a client connects, and
requests round-trip -- against a faked Session.  That covers the part most likely
to break silently: the boundary between the process holding the credentials and
the process asking it to do work.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from access_control.daemon import (
    SessionClient,
    SessionDescriptor,
    SessionServer,
    attach,
    descriptor_path,
    list_descriptors,
    read_descriptor,
)
from access_control.errors import AccessControlError
from access_control.transport.base import ExecResult


@pytest.fixture(autouse=True)
def isolated_session_dir(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("AC_DATA_DIR", str(tmp_path / "data"))
    return tmp_path


class ServableSession:
    """The subset of Session that SessionServer actually uses."""

    def __init__(self, host_id: str = "win01") -> None:
        self.host_id = host_id
        self.session_id = "20260101T000000Z-daemontest"
        self.agent_id = "pytest"
        self.audit = None
        self.expired = False
        self.touched = 0
        self.closed_with: str | None = None
        self.commands: list[str] = []

    def touch(self) -> None:
        self.touched += 1

    def status(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "host_id": self.host_id,
            "agent_id": self.agent_id,
            "connected": True,
            "steps_ok": 0,
            "steps_failed": 0,
        }

    def operations(self) -> list[dict[str, Any]]:
        return [{"id": "echo-op", "description": "test", "steps": [{"id": "first"}]}]

    def exec(self, command: str, **_kwargs: Any) -> ExecResult:
        self.commands.append(command)
        return ExecResult(
            node_id=self.host_id, channel="fake", command=command, exit_code=0, stdout="hi"
        )

    def close(self, status: str = "closed", **_kwargs: Any) -> dict[str, Any]:
        self.closed_with = status
        return {**self.status(), "status": status, "closed": True}


class RunningServer:
    """Start a SessionServer on a thread and hand back a connected client."""

    def __init__(self, session: ServableSession) -> None:
        self.session = session
        self.server = SessionServer(session)
        self.ready = threading.Event()
        self.descriptor: SessionDescriptor | None = None
        self.server.on_ready = self._on_ready
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _on_ready(self, descriptor: SessionDescriptor) -> None:
        self.descriptor = descriptor
        self.ready.set()

    def __enter__(self) -> tuple[SessionClient, "RunningServer"]:
        self.thread.start()
        assert self.ready.wait(timeout=10), "server did not start"
        assert self.descriptor is not None
        return SessionClient(self.descriptor, timeout=15), self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown("closed")
        self.thread.join(timeout=5)


class TestDescriptors:
    def test_round_trip(self) -> None:
        descriptor = SessionDescriptor(
            host_id="win01",
            session_id="s1",
            port=12345,
            token="tok",
            pid=999,
            started=time.time(),
            agent_id="pytest",
        )
        descriptor.write()
        loaded = read_descriptor("win01")
        assert loaded is not None
        assert loaded.port == 12345 and loaded.token == "tok"

    def test_missing_descriptor_returns_none(self) -> None:
        assert read_descriptor("never-existed") is None

    def test_corrupt_descriptor_is_ignored_rather_than_raising(self) -> None:
        path = descriptor_path("win01")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        assert read_descriptor("win01") is None

    def test_version_mismatch_is_ignored(self) -> None:
        path = descriptor_path("win01")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": 999, "host_id": "win01"}), encoding="utf-8")
        assert read_descriptor("win01") is None

    def test_host_ids_are_sanitised_into_filenames(self) -> None:
        assert "/" not in descriptor_path("a/b\\c").name

    def test_attach_removes_a_stale_descriptor(self) -> None:
        """A closed terminal leaves a descriptor behind; it must not mislead later."""
        SessionDescriptor(
            host_id="ghost",
            session_id="s",
            port=1,  # nothing is listening
            token="t",
            pid=0,
            started=time.time(),
            agent_id="a",
        ).write()
        assert attach("ghost") is None
        assert read_descriptor("ghost") is None


class TestProtocol:
    def test_ping_and_status(self) -> None:
        with RunningServer(ServableSession()) as (client, _):
            assert client.call("ping")["host_id"] == "win01"
            assert client.call("status")["session_id"].endswith("daemontest")

    def test_operations_are_served(self) -> None:
        with RunningServer(ServableSession()) as (client, _):
            assert [o["id"] for o in client.call("operations")] == ["echo-op"]

    def test_run_command_reaches_the_session(self) -> None:
        with RunningServer(ServableSession()) as (client, running):
            result = client.call("run_command", command="Get-Service W3SVC")
            assert result["exit_code"] == 0
            assert running.session.commands == ["Get-Service W3SVC"]

    def test_gated_command_is_refused_over_the_wire(self) -> None:
        with RunningServer(ServableSession()) as (client, running):
            with pytest.raises(AccessControlError, match="confirmation required"):
                client.call("run_command", command="Restart-Service W3SVC")
            assert running.session.commands == []

    def test_blocked_command_is_refused_even_with_confirmation(self) -> None:
        with RunningServer(ServableSession()) as (client, running):
            with pytest.raises(AccessControlError, match="never-run list"):
                client.call(
                    "run_command", command="Format-Volume -DriveLetter D", confirmed=True
                )
            assert running.session.commands == []

    def test_a_wrong_token_is_rejected(self) -> None:
        with RunningServer(ServableSession()) as (client, running):
            assert running.descriptor is not None
            impostor = SessionClient(
                SessionDescriptor(
                    host_id=running.descriptor.host_id,
                    session_id=running.descriptor.session_id,
                    port=running.descriptor.port,
                    token="wrong-token",
                    pid=0,
                    started=0.0,
                    agent_id="attacker",
                )
            )
            with pytest.raises(AccessControlError, match="invalid session token"):
                impostor.call("status")

    def test_unknown_method_is_reported_not_crashed(self) -> None:
        with RunningServer(ServableSession()) as (client, _):
            with pytest.raises(AccessControlError, match="unknown method"):
                client.call("definitely_not_a_method")
            # The session survives a bad request.
            assert client.call("ping")["host_id"] == "win01"

    def test_activity_keeps_the_session_alive(self) -> None:
        with RunningServer(ServableSession()) as (client, running):
            client.call("run_command", command="whoami")
            assert running.session.touched > 0

    def test_descriptor_is_visible_then_removed(self) -> None:
        with RunningServer(ServableSession()) as (client, _):
            assert [d.host_id for d in list_descriptors()] == ["win01"]
            assert client.alive()
        assert list_descriptors() == []

    def test_close_returns_the_report_before_tearing_down(self) -> None:
        """Found in live testing: `ac disconnect` got a connection error, not a report.

        Shutting down inside the handler raced the reply. PLAN.md requires the
        status to reach the operator *before* the session goes away, so the
        teardown is deferred until the reply is on the wire.
        """
        session = ServableSession()
        running = RunningServer(session)
        running.thread.start()
        assert running.ready.wait(timeout=10)
        assert running.descriptor is not None
        try:
            client = SessionClient(running.descriptor, timeout=15)
            report = client.call("close")
            assert report["host_id"] == "win01"
            assert report["closing"] is True
            assert report["status"] == "closed"
        finally:
            running.thread.join(timeout=10)
        assert session.closed_with is not None, "the session must still tear down"

    def test_close_is_reliable_across_repeated_runs(self) -> None:
        """The bug was intermittent, so prove it is not a coin flip."""
        for _ in range(5):
            session = ServableSession()
            running = RunningServer(session)
            running.thread.start()
            assert running.ready.wait(timeout=10)
            assert running.descriptor is not None
            try:
                report = SessionClient(running.descriptor, timeout=15).call("close")
                assert report["closing"] is True
            finally:
                running.thread.join(timeout=10)

    def test_shutdown_closes_the_session(self) -> None:
        session = ServableSession()
        with RunningServer(session):
            pass
        assert session.closed_with == "closed"

    def test_client_reports_a_dead_session_usefully(self) -> None:
        client = SessionClient(
            SessionDescriptor(
                host_id="win01",
                session_id="s",
                port=1,
                token="t",
                pid=0,
                started=0.0,
                agent_id="a",
            ),
            timeout=2,
        )
        with pytest.raises(AccessControlError, match="ac connect win01"):
            client.call("status")
