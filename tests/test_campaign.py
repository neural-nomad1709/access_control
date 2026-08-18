"""Campaign layer: parsing, offline planning, and concurrent dispatch."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from access_control.campaign import (
    Campaign,
    CampaignTarget,
    execute_brief_on_client,
    load_campaign,
    plan_campaign,
    run_campaign,
)
from access_control.config import load_all
from access_control.errors import ConfigError


# --------------------------------------------------------------------------
# Fixtures: a tiny inventory + catalogue + brief on disk
# --------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "inventory.yaml").write_text(
        textwrap.dedent(
            """
            hosts:
              win-a:
                kind: windows
                username: svc
                domain: corp
                tags: [windows]
                auth: {transport: ntlm}
                via: {from: local, hostname: 10.0.0.10, port: 5985, protocol: winrm}
              win-b:
                kind: windows
                username: svc
                domain: corp
                tags: [windows]
                auth: {transport: ntlm}
                via: {from: local, hostname: 10.0.0.11, port: 5985, protocol: winrm}
            """
        ).strip(),
        encoding="utf-8",
    )
    (cfg / "operations.yaml").write_text(
        textwrap.dedent(
            """
            operations:
              - id: windows-health
                description: read-only snapshot
                tags: [windows]
                requires_permission: false
                steps:
                  - id: snapshot
                    desc: snapshot
                    run: '"ok"'
            """
        ).strip(),
        encoding="utf-8",
    )
    (cfg / "brief.yaml").write_text(
        textwrap.dedent(
            """
            brief:
              id: health
              title: Health
              host: win-a
              change_ref: T-1
            operations:
              - operation: windows-health
            preflight: {expect_hostname: WIN-A}
            success_criteria: ["reported"]
            """
        ).strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("AC_CONFIG_DIR", str(cfg))
    inventory, catalog, _ = load_all()
    return {"cfg": cfg, "inventory": inventory, "catalog": catalog}


def _write_campaign(cfg: Path, body: str) -> Path:
    path = cfg / "campaign.yaml"
    path.write_text(textwrap.dedent(body).strip(), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_parse_requires_campaign_block():
    with pytest.raises(ConfigError, match="campaign.*block|campaign.id"):
        Campaign.parse({"targets": [{"host": "x", "brief": "b"}]})


def test_parse_requires_targets():
    with pytest.raises(ConfigError, match="targets"):
        Campaign.parse({"campaign": {"id": "c", "title": "t"}})


def test_target_requires_brief():
    with pytest.raises(ConfigError, match="brief"):
        CampaignTarget.parse({"host": "x"}, "targets[0]")


def test_max_parallel_floor():
    with pytest.raises(ConfigError, match="max_parallel"):
        Campaign.parse(
            {"campaign": {"id": "c", "title": "t", "max_parallel": 0}, "targets": [{"brief": "b"}]}
        )


# --------------------------------------------------------------------------
# Planning (offline validation + retargeting)
# --------------------------------------------------------------------------


def test_plan_retargets_brief_to_target_host(env):
    path = _write_campaign(
        env["cfg"],
        """
        campaign: {id: sweep, title: Sweep}
        targets:
          - {host: win-b, brief: brief.yaml}
        """,
    )
    campaign = load_campaign(path)
    plan, _ = plan_campaign(campaign, env["inventory"], env["catalog"])
    assert len(plan) == 1
    # The brief names win-a; the target overrode it to win-b.
    assert plan[0].host == "win-b"
    assert plan[0].brief.id == "health"


def test_plan_rejects_duplicate_host(env):
    path = _write_campaign(
        env["cfg"],
        """
        campaign: {id: sweep, title: Sweep}
        targets:
          - {host: win-a, brief: brief.yaml}
          - {host: win-a, brief: brief.yaml}
        """,
    )
    campaign = load_campaign(path)
    with pytest.raises(ConfigError, match="more than once"):
        plan_campaign(campaign, env["inventory"], env["catalog"])


def test_plan_rejects_unknown_host(env):
    path = _write_campaign(
        env["cfg"],
        """
        campaign: {id: sweep, title: Sweep}
        targets:
          - {host: ghost, brief: brief.yaml}
        """,
    )
    campaign = load_campaign(path)
    with pytest.raises(ConfigError, match="ghost"):
        plan_campaign(campaign, env["inventory"], env["catalog"])


# --------------------------------------------------------------------------
# Execution (with a fake session client -- no real WinRM)
# --------------------------------------------------------------------------


class FakeClient:
    """Stands in for a live SessionClient: records calls, returns canned replies."""

    def __init__(self, *, preflight_ok=True, op_ok=True):
        self.preflight_ok = preflight_ok
        self.op_ok = op_ok
        self.calls: list[str] = []

    def call(self, method, **kwargs):
        self.calls.append(method)
        if method == "preflight":
            return {"ok": self.preflight_ok, "checks": [{"name": "x", "detail": "d", "passed": self.preflight_ok}]}
        if method == "run_operation":
            return {"ok": self.op_ok, "operation_id": kwargs.get("operation_id")}
        raise AssertionError(method)


def _plan(env, hosts):
    body = "campaign: {id: sweep, title: Sweep}\ntargets:\n" + "\n".join(
        f"  - {{host: {h}, brief: brief.yaml}}" for h in hosts
    )
    path = _write_campaign(env["cfg"], body)
    campaign = load_campaign(path)
    return campaign, plan_campaign(campaign, env["inventory"], env["catalog"])[0]


def test_run_dispatches_to_each_live_session(env):
    campaign, plan = _plan(env, ["win-a", "win-b"])
    clients = {"win-a": FakeClient(), "win-b": FakeClient()}
    report = run_campaign(campaign, plan, attach=lambda h: clients.get(h))
    assert report.ok
    assert report.counts() == {"ok": 2}
    # Each target's brief actually ran preflight + the operation on its own client.
    assert clients["win-a"].calls == ["preflight", "run_operation"]


def test_run_skips_host_without_session(env):
    campaign, plan = _plan(env, ["win-a", "win-b"])
    only_a = {"win-a": FakeClient()}
    report = run_campaign(campaign, plan, attach=lambda h: only_a.get(h))
    counts = report.counts()
    assert counts.get("ok") == 1 and counts.get("skipped") == 1
    assert not report.ok  # a skipped host means the sweep was not fully applied


def test_preflight_failure_stops_that_target_only(env):
    campaign, plan = _plan(env, ["win-a", "win-b"])
    clients = {"win-a": FakeClient(preflight_ok=False), "win-b": FakeClient()}
    report = run_campaign(campaign, plan, attach=lambda h: clients.get(h))
    by_host = {r.host: r for r in report.results}
    assert by_host["win-a"].status == "preflight-failed"
    assert by_host["win-b"].status == "ok"
    # win-a never ran the operation; win-b was unaffected.
    assert clients["win-a"].calls == ["preflight"]


def test_execute_brief_reports_operation_failure(env):
    _, plan = _plan(env, ["win-a"])
    result = execute_brief_on_client(FakeClient(op_ok=False), plan[0].brief, confirm=False)
    assert result.status == "failed"
