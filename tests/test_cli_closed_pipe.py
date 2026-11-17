"""A reader that stops early (`ac ops | Select-Object -First 3`, `ac ops | head`)
is normal use, not a crash.

Windows reports a write to a closed pipe as ``OSError`` errno 22, POSIX as
``BrokenPipeError``. Either way ``ac`` stops quietly: no traceback in
``errors.log`` and nothing on stderr.
"""

from __future__ import annotations

import errno
import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from access_control import cli


class ClosedPipe(io.StringIO):
    def write(self, text: str) -> int:
        raise OSError(errno.EINVAL, "Invalid argument")

    def flush(self) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")


class TestStdoutGuard:
    def test_a_failed_write_is_reported_as_a_broken_pipe(self) -> None:
        with pytest.raises(BrokenPipeError):
            cli._StdoutGuard(ClosedPipe()).write("x")

    def test_a_failed_flush_is_reported_as_a_broken_pipe(self) -> None:
        with pytest.raises(BrokenPipeError):
            cli._StdoutGuard(ClosedPipe()).flush()

    def test_an_open_stream_is_written_through(self) -> None:
        stream = io.StringIO()
        guard = cli._StdoutGuard(stream)
        guard.write("hello")
        guard.flush()
        assert stream.getvalue() == "hello"

    def test_everything_else_is_the_wrapped_stream(self) -> None:
        stream = io.StringIO()
        assert cli._StdoutGuard(stream).getvalue is not None
        assert cli._StdoutGuard(sys.__stdout__).encoding == sys.__stdout__.encoding


class TestMain:
    def test_a_broken_pipe_exits_quietly_without_a_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        monkeypatch.setenv("AC_DATA_DIR", str(tmp_path))
        monkeypatch.setattr(cli, "_quiet_stdout_after_broken_pipe", lambda: None)

        def reader_gone() -> None:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        monkeypatch.setattr(cli, "app", reader_gone)
        monkeypatch.setattr(sys, "argv", ["ac", "ops"])
        with pytest.raises(SystemExit) as stopped:
            cli.main()
        assert stopped.value.code == 1
        assert capsys.readouterr().err == ""
        assert not (tmp_path / "logs" / "errors.log").exists()

    def test_an_unrelated_oserror_is_still_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AC_DATA_DIR", str(tmp_path))

        def real_failure() -> None:
            raise OSError(errno.EINVAL, "bad path")

        monkeypatch.setattr(cli, "app", real_failure)
        monkeypatch.setattr(sys, "argv", ["ac", "ops"])
        with pytest.raises(SystemExit):
            cli.main()
        assert "bad path" in (tmp_path / "logs" / "errors.log").read_text(encoding="utf-8")


def test_a_reader_that_stops_early_leaves_no_traceback(tmp_path: Path) -> None:
    """The real CLI in a real process, its reader closed before it writes."""
    env = {**os.environ, "AC_DATA_DIR": str(tmp_path)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "access_control.cli", "--help"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    assert proc.stdout is not None and proc.stderr is not None
    proc.stdout.close()
    stderr = proc.stderr.read().decode("utf-8", "replace")
    proc.wait(timeout=60)

    assert not (tmp_path / "logs" / "errors.log").exists(), (
        (tmp_path / "logs" / "errors.log").read_text(encoding="utf-8"))
    assert stderr == ""
    assert proc.returncode == 1
