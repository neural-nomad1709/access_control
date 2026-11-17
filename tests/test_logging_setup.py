"""The library log: its level follows ``logging.level`` (F-05) and neither it
nor ``errors.log`` grows without bound (F-06).

``logging.level`` applies to ``transport.log`` only. The audit trail is evidence
and is never filtered by level.
"""

from __future__ import annotations

import logging
import textwrap
from pathlib import Path

import pytest

from access_control import logging_setup
from access_control.config import load_inventory, load_operations


@pytest.fixture
def log_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A private log directory and a clean slate for the module's one-time setup."""
    monkeypatch.setenv("AC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(logging_setup, "_installed", None)
    saved = {
        name: (list(logging.getLogger(name).handlers), logging.getLogger(name).level,
               logging.getLogger(name).propagate)
        for name in logging_setup.NOISY_LOGGERS
    }
    yield tmp_path / "data" / "logs"
    for name, (handlers, level, propagate) in saved.items():
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            if handler not in handlers:
                handler.close()
        logger.handlers, logger.propagate = handlers, propagate
        logger.setLevel(level)


class TestLibraryLogLevel:
    def test_default_stays_at_warning(self, log_home: Path) -> None:
        logging_setup.install_quiet_logging()
        logging.getLogger("paramiko").info("handshake detail")
        logging.getLogger("paramiko").warning("something odd")
        text = (log_home / "transport.log").read_text(encoding="utf-8")
        assert "something odd" in text and "handshake detail" not in text

    def test_debug_level_records_library_detail(self, log_home: Path) -> None:
        logging_setup.install_quiet_logging()
        logging_setup.set_library_log_level("DEBUG")
        logging.getLogger("paramiko").debug("kex detail")
        assert "kex detail" in (log_home / "transport.log").read_text(encoding="utf-8")

    def test_error_level_drops_warnings(self, log_home: Path) -> None:
        logging_setup.install_quiet_logging()
        logging_setup.set_library_log_level("ERROR")
        logging.getLogger("paramiko").warning("benign oddity")
        logging.getLogger("paramiko").error("real failure")
        text = (log_home / "transport.log").read_text(encoding="utf-8")
        assert "real failure" in text and "benign oddity" not in text

    def test_build_session_applies_the_inventory_level(
        self, log_home: Path, config_files: Path
    ) -> None:
        from access_control.daemon import build_session

        inventory_file = config_files / "inventory.yaml"
        inventory_file.write_text(
            "logging:\n  level: ERROR\n" + inventory_file.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        logging_setup.install_quiet_logging()
        build_session(
            "lin01",
            inventory=load_inventory(inventory_file),
            catalog=load_operations(config_files / "operations.yaml"),
        )
        assert logging.getLogger("paramiko").level == logging.ERROR

    def test_the_audit_trail_is_not_filtered_by_level(
        self, log_home: Path, config_files: Path
    ) -> None:
        from access_control.daemon import build_session

        inventory_file = config_files / "inventory.yaml"
        inventory_file.write_text(
            "logging:\n  level: ERROR\n" + inventory_file.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        session = build_session(
            "lin01",
            inventory=load_inventory(inventory_file),
            catalog=load_operations(config_files / "operations.yaml"),
        )
        session.audit.action("TUNNEL_OPEN", target="x:1")
        assert [r["action"] for r in session.audit.records] == ["TUNNEL_OPEN"]
        assert "TUNNEL_OPEN" in session.audit.path.read_text(encoding="utf-8")


class TestTransportLogIsBounded:
    def test_it_rotates_and_keeps_a_fixed_number_of_backups(
        self, log_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(logging_setup, "MAX_LOG_BYTES", 2_000)
        monkeypatch.setattr(logging_setup, "LOG_BACKUPS", 2)
        logging_setup.install_quiet_logging()
        for i in range(400):
            logging.getLogger("paramiko").warning("record %04d %s", i, "x" * 60)

        files = sorted(p.name for p in log_home.glob("transport.log*"))
        assert files == ["transport.log", "transport.log.1", "transport.log.2"]
        assert all(p.stat().st_size <= 2_500 for p in log_home.glob("transport.log*"))

    def test_a_failed_rotation_neither_raises_nor_prints(
        self, log_home: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """On Windows a second ``ac`` process holding the file blocks the rename."""
        monkeypatch.setattr(logging_setup, "MAX_LOG_BYTES", 200)
        logging_setup.install_quiet_logging()
        handler = logging.getLogger("paramiko").handlers[0]

        def locked(source: str, dest: str) -> None:
            raise PermissionError("file in use by another process")

        monkeypatch.setattr(handler, "rotate", locked)
        for i in range(20):
            logging.getLogger("paramiko").warning("record %d %s", i, "y" * 60)

        assert capsys.readouterr().err == ""
        assert "record 19" in (log_home / "transport.log").read_text(encoding="utf-8")


class TestErrorsLogIsBounded:
    def _boom(self, text: str) -> Exception:
        try:
            raise RuntimeError(text)
        except RuntimeError as exc:
            return exc

    def test_it_rolls_over_to_one_backup(
        self, log_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(logging_setup, "MAX_LOG_BYTES", 600)
        for i in range(12):
            logging_setup.record_unexpected(self._boom(f"failure {i}"), context="test")

        files = sorted(p.name for p in log_home.glob("errors.log*"))
        assert files == ["errors.log", "errors.log.1"]
        assert "failure 11" in (log_home / "errors.log").read_text(encoding="utf-8")

    def test_a_small_file_is_left_alone(self, log_home: Path) -> None:
        logging_setup.record_unexpected(self._boom("only one"), context="test")
        assert [p.name for p in log_home.glob("errors.log*")] == ["errors.log"]
