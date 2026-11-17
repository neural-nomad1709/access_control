"""F-11: a brief's ``rules.max_duration_minutes`` is a ceiling, not a note.

``ac brief run`` starts no further operation once the ceiling has passed. It
cannot interrupt an operation already running (step timeouts bound those), so
the guarantee is "nothing new starts late". The clock is injected by replacing
the ``time`` module the command reads, and the recording client advances it as
each operation "runs".
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from access_control import cli

from test_cli_brief_postcheck import RecordingClient, write_brief

BRIEF = """
brief:
  id: TB-DUR
  title: Two operations under a ceiling
  host: win01
  requested_by: tester
  change_ref: CHG1
operations:
  - operation: echo-op
    params: {{message: first}}
  - operation: windows-only
postcheck:
  expect_service_running: [W3SVC]
rules:
  max_duration_minutes: {minutes}
"""


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class SlowClient(RecordingClient):
    """Each operation takes ``seconds`` of the injected clock."""

    def __init__(self, clock: Clock, seconds: float) -> None:
        super().__init__()
        self.clock, self.seconds = clock, seconds

    def call(self, method: str, **kwargs: Any) -> dict[str, Any]:
        if method == "run_operation":
            self.clock.now += self.seconds
        return super().call(method, **kwargs)

    def operations_run(self) -> list[str]:
        return [kw["operation_id"] for m, kw in self.calls if m == "run_operation"]


@pytest.fixture
def run(config_files: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AC_CONFIG_DIR", str(config_files))
    clock = Clock()
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=clock.monotonic))

    def invoke(minutes: int, seconds_per_operation: float) -> tuple[Any, SlowClient]:
        client = SlowClient(clock, seconds_per_operation)
        monkeypatch.setattr(cli, "_client_or_fail", lambda host: client)
        path = write_brief(tmp_path, BRIEF.format(minutes=minutes))
        return CliRunner().invoke(cli.app, ["brief", "run", str(path), "--skip-preflight"]), client

    return invoke


class TestDurationCeiling:
    def test_no_operation_starts_after_the_ceiling(self, run) -> None:
        result, client = run(minutes=1, seconds_per_operation=90)

        assert result.exit_code == 2, result.output
        assert client.operations_run() == ["echo-op"]
        output = result.output.replace("\n", " ")
        assert "max_duration_minutes" in output and "windows-only" in output

    def test_the_postcheck_is_skipped_when_the_ceiling_stopped_the_brief(self, run) -> None:
        _result, client = run(minutes=1, seconds_per_operation=90)
        assert client.preflight_specs() == []

    def test_within_the_ceiling_everything_runs(self, run) -> None:
        result, client = run(minutes=5, seconds_per_operation=90)

        assert result.exit_code == 0, result.output
        assert client.operations_run() == ["echo-op", "windows-only"]
        assert client.preflight_specs() == [{"expect_service_running": ["W3SVC"]}]

    def test_zero_means_no_ceiling(self, run) -> None:
        result, client = run(minutes=0, seconds_per_operation=10_000)

        assert result.exit_code == 0, result.output
        assert client.operations_run() == ["echo-op", "windows-only"]
