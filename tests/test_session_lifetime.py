"""F-04: an absolute session lifetime, alongside the idle timeout.

The idle timer resets on every command, so a session driven continuously (a
long campaign, or an agent that never pauses) holds a credentialed multi-hop
path open forever. An absolute ceiling — measured from connect, never
refreshed — bounds that, independent of activity. Zero means no ceiling
(today's behaviour, the default).
"""

from __future__ import annotations

import time

import pytest

from access_control.config import load_inventory, load_operations
from access_control.errors import SessionError
from access_control.session import Session


@pytest.fixture
def session(config_files):
    return Session(
        inventory=load_inventory(config_files / "inventory.yaml"),
        catalog=load_operations(config_files / "operations.yaml"),
        host_id="lin01",
    )


def _mark_connected(session: Session, *, connected_at: float, last_used: float) -> None:
    """Pretend the session connected and last ran at these times, without a
    socket — the lifetime clock reads connected_at, the idle clock last_used."""
    session.channel = object()
    session.connected_at = connected_at
    session.last_used = last_used


class TestLifetimeExpiry:
    def test_default_is_no_absolute_ceiling(self, session) -> None:
        assert session.max_lifetime_s == 0
        _mark_connected(session, connected_at=time.time() - 10_000,
                        last_used=time.time())
        assert not session.expired  # active, no idle lapse, no ceiling

    def test_lifetime_expires_even_under_continuous_activity(self, session) -> None:
        session.idle_timeout_s = 1800     # nowhere near lapsing
        session.max_lifetime_s = 3600
        # connected 2 hours ago, but used one second ago: never idle
        _mark_connected(session, connected_at=time.time() - 7200,
                        last_used=time.time())
        assert session.expired
        assert not session.active

    def test_within_the_ceiling_a_busy_session_stays_up(self, session) -> None:
        session.max_lifetime_s = 3600
        _mark_connected(session, connected_at=time.time() - 60,
                        last_used=time.time())
        assert not session.expired

    def test_idle_expiry_still_fires_below_the_ceiling(self, session) -> None:
        session.idle_timeout_s = 60
        session.max_lifetime_s = 86_400
        _mark_connected(session, connected_at=time.time() - 120,
                        last_used=time.time() - 120)
        assert session.expired  # idle, well within the lifetime ceiling


class TestLifetimeReporting:
    def test_require_active_names_the_lifetime_cap(self, session) -> None:
        session.max_lifetime_s = 3600
        _mark_connected(session, connected_at=time.time() - 7200,
                        last_used=time.time())
        with pytest.raises(SessionError, match="maximum lifetime"):
            session.require_active()

    def test_status_reports_the_lifetime_and_remaining(self, session) -> None:
        session.max_lifetime_s = 3600
        _mark_connected(session, connected_at=time.time() - 600,
                        last_used=time.time())
        status = session.status()
        assert status["max_lifetime_s"] == 3600
        assert 0 < status["lifetime_remaining_s"] <= 3600

    def test_no_ceiling_reports_none(self, session) -> None:
        _mark_connected(session, connected_at=time.time(), last_used=time.time())
        status = session.status()
        assert status["max_lifetime_s"] == 0
        assert status["lifetime_remaining_s"] is None


class TestBuildSessionWiring:
    def test_build_session_threads_the_ceiling_through(self, config_files, monkeypatch):
        from access_control.daemon import build_session

        monkeypatch.setenv("AC_DATA_DIR", str(config_files.parent / "data"))
        session = build_session(
            "lin01",
            inventory=load_inventory(config_files / "inventory.yaml"),
            catalog=load_operations(config_files / "operations.yaml"),
            max_lifetime_s=3600,
        )
        assert session.max_lifetime_s == 3600
