"""Campaigns: run one instruction across many hosts, concurrently.

A campaign is a *fan-out* -- the Supervisor pattern from multi-agent orchestration.
It names a set of targets, each a ``(host, brief)`` pair, and dispatches each
brief to that host's OWN already-authenticated session.

Two principles, both deliberate:

*The instruction is central, never on the target.* A campaign references briefs
that live in the repo -- reviewed, version-controlled, validated before anything
connects. The target machine is only ever *acted upon*; it never supplies the
agent's instructions. That keeps a compromised host from commanding a privileged,
credentialed session (the "lethal trifecta" failure mode).

*Credentials are not handled here.* An operator opens each host's session with
``uv run ac connect <host>`` -- entering that host's password once -- and the
campaign attaches to the live sessions by host id. A host with no live session is
reported and skipped, not connected to. Scaling the credential step (a broker or
vault) is a separate decision this module intentionally does not make.

The same brief can be pointed at many hosts: a target may override the brief's
own ``host``, so one reviewed instruction template runs across a fleet.
"""

from __future__ import annotations

import dataclasses
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import yaml

from .brief import TaskBrief, load_brief, validate_brief
from .config import Catalog, Inventory
from .errors import ConfigError

DEFAULT_MAX_PARALLEL = 8


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where}: expected a mapping")
    return dict(value)


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CampaignTarget:
    """One host in a campaign, and the brief to run on it."""

    brief: str
    #: Overrides the brief's own ``host`` so one brief template can run on many
    #: hosts. When omitted, the brief runs against the host it names itself.
    host: str | None = None
    note: str = ""

    @classmethod
    def parse(cls, raw: Any, where: str) -> "CampaignTarget":
        data = _mapping(raw, where)
        brief = data.get("brief")
        if not brief:
            raise ConfigError(f"{where}: missing 'brief' (path to the instruction document)")
        return cls(
            brief=str(brief),
            host=(str(data["host"]) if data.get("host") else None),
            note=str(data.get("note", "")),
        )


@dataclass(frozen=True)
class Campaign:
    """A set of targets to run in one fan-out."""

    id: str
    title: str
    targets: tuple[CampaignTarget, ...]
    requested_by: str = ""
    change_ref: str = ""
    description: str = ""
    #: Ceiling on how many hosts are driven at once. Each target attaches to its
    #: own daemon, so this bounds concurrency, not a shared resource.
    max_parallel: int = DEFAULT_MAX_PARALLEL
    #: Whether gated operations are pre-approved for the whole campaign. Off by
    #: default: a destructive fan-out should be an explicit choice.
    confirm: bool = False
    source: Path | None = None

    @classmethod
    def parse(cls, raw: Mapping[str, Any], source: Path | None = None) -> "Campaign":
        data = dict(raw)
        head = _mapping(data.get("campaign"), "campaign")
        if not head:
            raise ConfigError(
                "a campaign must start with a 'campaign:' block containing at least id and title"
            )
        for required in ("id", "title"):
            if not head.get(required):
                raise ConfigError(f"campaign.{required}: required")

        targets_raw = data.get("targets")
        if not targets_raw:
            raise ConfigError(
                "targets: required -- a campaign with no targets does nothing. List the "
                "hosts and the brief to run on each."
            )
        if isinstance(targets_raw, Mapping):
            targets_raw = [targets_raw]
        if not isinstance(targets_raw, Sequence) or isinstance(targets_raw, str):
            raise ConfigError("targets: expected a list of {host, brief} entries")
        targets = tuple(
            CampaignTarget.parse(item, f"targets[{i}]") for i, item in enumerate(targets_raw)
        )

        max_parallel = int(head.get("max_parallel", DEFAULT_MAX_PARALLEL))
        if max_parallel < 1:
            raise ConfigError("campaign.max_parallel: must be at least 1")

        return cls(
            id=str(head["id"]),
            title=str(head["title"]),
            targets=targets,
            requested_by=str(head.get("requested_by", "")),
            change_ref=str(head.get("change_ref", "")),
            description=str(head.get("description", "")),
            max_parallel=max_parallel,
            confirm=bool(head.get("confirm", False)),
            source=source,
        )

    def render(self) -> str:
        lines = [f"{self.id}  {self.title}"]
        for label, value in (
            ("requested by", self.requested_by),
            ("change ref", self.change_ref),
        ):
            if value:
                lines.append(f"  {label:<13} {value}")
        lines.append(f"  parallelism   {self.max_parallel}")
        lines.append(f"  confirm gated {self.confirm}")
        if self.description:
            lines += ["", f"  {self.description.strip()}"]
        lines += ["", "  targets:"]
        for i, t in enumerate(self.targets, 1):
            host = t.host or "(brief's own host)"
            note = f"  # {t.note}" if t.note else ""
            lines.append(f"    {i}. {host:<24} {t.brief}{note}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Loading and validation
# --------------------------------------------------------------------------


def load_campaign(path: str | Path) -> Campaign:
    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise ConfigError(f"campaign not found: {resolved}")
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{resolved} is not valid YAML: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{resolved}: top level must be a mapping")
    return Campaign.parse(raw, source=resolved)


@dataclass(frozen=True)
class PlannedTarget:
    """A campaign target whose brief has been loaded and retargeted to its host."""

    target: CampaignTarget
    brief: TaskBrief
    warnings: tuple[str, ...] = ()

    @property
    def host(self) -> str:
        return self.brief.host


def _resolve_brief_path(campaign: Campaign, brief_ref: str) -> Path:
    """Resolve a target's brief path, relative to the campaign file if needed."""
    p = Path(brief_ref).expanduser()
    if p.is_absolute() or p.exists():
        return p
    if campaign.source is not None:
        # Repo-relative or campaign-relative, so a campaign can name briefs by a
        # path that reads naturally from where it lives.
        for base in (Path.cwd(), campaign.source.parent, campaign.source.parent.parent):
            candidate = (base / brief_ref)
            if candidate.exists():
                return candidate
    return p


def plan_campaign(
    campaign: Campaign, inventory: Inventory, catalog: Catalog
) -> tuple[list[PlannedTarget], list[str]]:
    """Load and validate every target's brief, offline. Connects to nothing.

    Each brief is retargeted to the target's host (so one template serves many
    hosts) and validated against the inventory and catalogue exactly as
    ``ac brief validate`` would. Raises if any target is unexecutable; returns
    the plan and the collected advisory warnings otherwise.
    """
    planned: list[PlannedTarget] = []
    warnings: list[str] = []
    problems: list[str] = []
    seen_hosts: set[str] = set()

    for index, target in enumerate(campaign.targets, 1):
        where = f"campaign '{campaign.id}' target {index}"
        try:
            brief = load_brief(_resolve_brief_path(campaign, target.brief))
        except ConfigError as exc:
            problems.append(f"{where}: {exc}")
            continue

        if target.host:
            brief = dataclasses.replace(brief, host=target.host)

        if brief.host in seen_hosts:
            problems.append(
                f"{where}: host '{brief.host}' appears more than once in this campaign. "
                f"A host has one session; give it a single target."
            )
            continue
        seen_hosts.add(brief.host)

        try:
            target_warnings = validate_brief(brief, inventory, catalog)
        except ConfigError as exc:
            problems.append(f"{where} (host '{brief.host}'): {exc}")
            continue

        warnings.extend(f"{brief.host}: {w}" for w in target_warnings)
        planned.append(PlannedTarget(target=target, brief=brief, warnings=tuple(target_warnings)))

    if problems:
        raise ConfigError(
            f"campaign '{campaign.id}' cannot be executed:\n  - " + "\n  - ".join(problems)
        )
    return planned, warnings


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


@dataclass
class TargetResult:
    """The outcome of running one target's brief."""

    host: str
    brief_id: str
    status: str  # "ok" | "failed" | "skipped" | "preflight-failed" | "error"
    detail: str = ""
    operations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "brief_id": self.brief_id,
            "status": self.status,
            "detail": self.detail,
            "operations": self.operations,
        }


@dataclass
class CampaignReport:
    campaign_id: str
    results: list[TargetResult]

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.results)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.results:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "ok": self.ok,
            "counts": self.counts(),
            "results": [r.to_dict() for r in self.results],
        }


def execute_brief_on_client(client: Any, brief: TaskBrief, *, confirm: bool) -> TargetResult:
    """Run one brief against an already-attached session client.

    Mirrors ``ac brief run``: preflight, then each operation in order, honouring
    per-step ``on_failure``. Returns a structured result; prints nothing, so it
    is safe to run from many threads at once.
    """
    try:
        report = client.call("preflight", spec=dict(brief.preflight))
    except Exception as exc:  # noqa: BLE001 - any client/transport error is this target's problem alone
        return TargetResult(brief.host, brief.id, "error", f"preflight call failed: {exc}")
    if not report.get("ok"):
        failed = [c for c in report.get("checks", []) if not c.get("passed")]
        detail = "; ".join(f"{c['name']}: {c['detail']}" for c in failed) or "preflight failed"
        return TargetResult(brief.host, brief.id, "preflight-failed", detail)

    results: list[dict[str, Any]] = []
    failed = False
    for step in brief.operations:
        try:
            res = client.call(
                "run_operation",
                operation_id=step.operation,
                params=dict(step.params),
                confirmed=confirm,
                start_at=step.start_at,
                only_steps=list(step.only_steps) or None,
            )
        except Exception as exc:  # noqa: BLE001
            results.append({"operation": step.operation, "ok": False, "error": str(exc)})
            failed = True
            break
        results.append(res)
        if not res.get("ok"):
            failed = True
            if step.on_failure == "continue":
                failed = False
                continue
            break

    status = "failed" if failed else "ok"
    detail = "" if not failed else "one or more operations failed"
    return TargetResult(brief.host, brief.id, status, detail, operations=results)


def run_campaign(
    campaign: Campaign,
    plan: Sequence[PlannedTarget],
    *,
    confirm: bool = False,
    max_parallel: int | None = None,
    attach: Callable[[str], Any] | None = None,
    execute: Callable[..., TargetResult] | None = None,
    on_event: Callable[[str, str, str], None] | None = None,
) -> CampaignReport:
    """Dispatch every planned target concurrently, one session per host.

    ``attach`` maps a host id to a live session client (or None if none is open);
    it defaults to the daemon attach, and is injectable for testing. ``execute``
    runs a brief against a client. ``on_event(kind, host, detail)`` reports
    progress (``start`` / ``done`` / ``skipped``).
    """
    if attach is None:
        from .daemon import attach as _attach

        attach = _attach
    if execute is None:
        execute = execute_brief_on_client
    confirm = confirm or campaign.confirm
    workers = max(1, min(max_parallel or campaign.max_parallel, len(plan) or 1))

    def _emit(kind: str, host: str, detail: str = "") -> None:
        if on_event is not None:
            on_event(kind, host, detail)

    def _run(pt: PlannedTarget) -> TargetResult:
        host = pt.host
        client = attach(host)
        if client is None:
            _emit("skipped", host, "no live session")
            return TargetResult(
                host,
                pt.brief.id,
                "skipped",
                "no live session -- open one first:  uv run ac connect " + host,
            )
        _emit("start", host, pt.brief.id)
        try:
            result = execute(client, pt.brief, confirm=confirm)
        except Exception as exc:  # noqa: BLE001 - isolate one target's failure from the fleet
            result = TargetResult(host, pt.brief.id, "error", str(exc))
        _emit("done", host, result.status)
        return result

    results: list[TargetResult]
    if workers == 1:
        results = [_run(pt) for pt in plan]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_run, plan))

    return CampaignReport(campaign_id=campaign.id, results=results)
