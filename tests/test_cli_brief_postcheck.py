"""F-08: a brief's ``postcheck:`` block must actually run.

``postcheck`` has the same shape as ``preflight`` and is verified by the same
daemon handler; historically it was parsed, shown by ``ac brief show --json``,
and then dropped. These tests drive the real ``brief run`` command with a
recording client standing in for the daemon, which is where the defect lives.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from access_control import cli

BRIEF_WITH_POSTCHECK = """
brief:
  id: TB-PC1
  title: Install then verify
  host: win01
  requested_by: tester
  change_ref: CHG1
preflight:
  expect_hostname: WIN01
operations:
  - operation: echo-op
    params: {message: hello}
postcheck:
  expect_service_running: [W3SVC]
success_criteria:
  - It worked
"""

BRIEF_WITHOUT_POSTCHECK = """
brief:
  id: TB-PC2
  title: Install only
  host: win01
  requested_by: tester
  change_ref: CHG1
preflight:
  expect_hostname: WIN01
operations:
  - operation: echo-op
    params: {message: hello}
"""


class RecordingClient:
    """Answers the daemon protocol calls ``brief run`` makes, recording them."""

    def __init__(
        self,
        *,
        operation_ok: bool = True,
        check_ok: dict[str, bool] | None = None,
    ) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.operation_ok = operation_ok
        # keyed by a spec key so preflight and postcheck can differ
        self.check_ok = check_ok or {}

    def call(self, method: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, kwargs))
        if method == "preflight":
            spec = kwargs.get("spec") or {}
            ok = all(self.check_ok.get(key, True) for key in spec)
            return {
                "ok": ok,
                "checks": [
                    {
                        "name": key,
                        "passed": self.check_ok.get(key, True),
                        "detail": "as expected" if self.check_ok.get(key, True) else "mismatch",
                        "remedy": "",
                    }
                    for key in spec
                ],
                "blockers": [] if ok else ["mismatch"],
            }
        if method == "run_operation":
            return {
                "ok": self.operation_ok,
                "operation_id": kwargs.get("operation_id"),
                "host_id": "win01",
                "status": "ok" if self.operation_ok else "failed",
                "duration_s": 0.1,
                "steps": [],
            }
        return {}

    def preflight_specs(self) -> list[dict[str, Any]]:
        return [kwargs.get("spec") or {} for method, kwargs in self.calls if method == "preflight"]


@pytest.fixture
def brief_env(config_files: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AC_CONFIG_DIR", str(config_files))
    return config_files


def write_brief(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "brief.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def run_brief(
    monkeypatch: pytest.MonkeyPatch, client: RecordingClient, brief_path: Path
) -> Any:
    monkeypatch.setattr(cli, "_client_or_fail", lambda host: client)
    return CliRunner().invoke(cli.app, ["brief", "run", str(brief_path)])


class TestPostcheckExecution:
    def test_postcheck_runs_after_successful_operations(
        self, brief_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = RecordingClient()
        result = run_brief(monkeypatch, client, write_brief(tmp_path, BRIEF_WITH_POSTCHECK))

        assert result.exit_code == 0, result.output
        specs = client.preflight_specs()
        assert {"expect_service_running": ["W3SVC"]} in specs, (
            f"postcheck spec never reached the daemon; preflight calls seen: {specs}"
        )
        # order: preflight first, operations, then postcheck last
        assert client.calls[-1][0] == "preflight"

    def test_postcheck_failure_fails_the_brief(
        self, brief_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = RecordingClient(check_ok={"expect_service_running": False})
        result = run_brief(monkeypatch, client, write_brief(tmp_path, BRIEF_WITH_POSTCHECK))

        assert result.exit_code == 2, result.output
        assert "postcheck" in result.output

    def test_postcheck_is_skipped_when_an_operation_failed(
        self, brief_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = RecordingClient(operation_ok=False)
        result = run_brief(monkeypatch, client, write_brief(tmp_path, BRIEF_WITH_POSTCHECK))

        assert result.exit_code == 2, result.output
        # only the opening preflight ran; a postcheck against a failed change
        # would assert expectations the operations never established
        assert client.preflight_specs() == [{"expect_hostname": "WIN01"}]

    def test_no_postcheck_block_means_no_extra_call(
        self, brief_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = RecordingClient()
        result = run_brief(monkeypatch, client, write_brief(tmp_path, BRIEF_WITHOUT_POSTCHECK))

        assert result.exit_code == 0, result.output
        assert client.preflight_specs() == [{"expect_hostname": "WIN01"}]
