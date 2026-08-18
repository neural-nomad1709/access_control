"""Task briefs: the instruction document that tells the agent what to do.

There are two config files for two different questions, and keeping them apart is
the point:

``operations.yaml``
    *What may ever be run.* A reviewed, version-controlled catalogue of
    capabilities. Changes to it are a code review.

**a task brief**
    *What to do this time.* One host, an ordered list of operations from that
    catalogue, the conditions that must hold before starting, what "done" looks
    like, and the rules the agent must obey. Written per change, per night, per
    ticket.

A brief is not free-form prose. It is validated before anything connects: every
operation must exist and be permitted on the host, every parameter must be
declared, the host must resolve to a route. An instruction the agent cannot
follow exactly is rejected while it is still cheap to fix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .config import Catalog, Inventory
from .errors import ConfigError
from .route import plan_route

ON_FAILURE_MODES = frozenset({"stop", "continue", "rollback"})


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where}: expected a mapping")
    return dict(value)


def _str_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence):
        return [str(v) for v in value]
    raise ConfigError(f"{where}: expected a string or a list of strings")


# --------------------------------------------------------------------------
# Pieces
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BriefStep:
    """One operation to run, and what to do if it fails."""

    operation: str
    params: Mapping[str, Any] = field(default_factory=dict)
    on_failure: str = "stop"
    start_at: str | None = None
    only_steps: tuple[str, ...] = ()
    note: str = ""

    @classmethod
    def parse(cls, raw: Any, where: str) -> "BriefStep":
        if isinstance(raw, str):
            return cls(operation=raw)
        data = _mapping(raw, where)
        operation = data.get("operation") or data.get("id")
        if not operation:
            raise ConfigError(f"{where}: missing 'operation'")
        mode = str(data.get("on_failure", "stop")).lower()
        if mode not in ON_FAILURE_MODES:
            raise ConfigError(
                f"{where}.on_failure: '{mode}' is not one of {sorted(ON_FAILURE_MODES)}"
            )
        return cls(
            operation=str(operation),
            params=_mapping(data.get("params"), f"{where}.params"),
            on_failure=mode,
            start_at=(str(data["start_at"]) if data.get("start_at") else None),
            only_steps=tuple(_str_list(data.get("only_steps"), f"{where}.only_steps")),
            note=str(data.get("note", "")),
        )


@dataclass(frozen=True)
class BriefRules:
    """The boundaries the agent must not cross while executing this brief."""

    #: Every gated operation still needs the operator's explicit approval.
    confirm_destructive: bool = True
    #: Stop the whole brief at the first failed operation.
    stop_on_first_failure: bool = True
    #: Refuse the brief outright if it would reboot anything.
    reboot_allowed: bool = False
    #: Wall-clock ceiling for the whole brief.
    max_duration_minutes: int = 120
    #: Ad-hoc commands allowed for diagnosis when something fails.
    allow_diagnostic_commands: bool = True
    #: Operations the agent may run beyond those listed, if any.
    allow_unlisted_operations: bool = False

    @classmethod
    def parse(cls, raw: Any, where: str) -> "BriefRules":
        data = _mapping(raw, where)
        unknown = set(data) - {
            "confirm_destructive",
            "stop_on_first_failure",
            "reboot_allowed",
            "max_duration_minutes",
            "allow_diagnostic_commands",
            "allow_unlisted_operations",
        }
        if unknown:
            raise ConfigError(
                f"{where}: unknown rule(s) {sorted(unknown)}. A misspelled rule would be "
                f"silently ignored, so it is rejected instead."
            )
        return cls(
            confirm_destructive=bool(data.get("confirm_destructive", True)),
            stop_on_first_failure=bool(data.get("stop_on_first_failure", True)),
            reboot_allowed=bool(data.get("reboot_allowed", False)),
            max_duration_minutes=int(data.get("max_duration_minutes", 120)),
            allow_diagnostic_commands=bool(data.get("allow_diagnostic_commands", True)),
            allow_unlisted_operations=bool(data.get("allow_unlisted_operations", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirm_destructive": self.confirm_destructive,
            "stop_on_first_failure": self.stop_on_first_failure,
            "reboot_allowed": self.reboot_allowed,
            "max_duration_minutes": self.max_duration_minutes,
            "allow_diagnostic_commands": self.allow_diagnostic_commands,
            "allow_unlisted_operations": self.allow_unlisted_operations,
        }


@dataclass(frozen=True)
class TaskBrief:
    """One instruction document."""

    id: str
    title: str
    host: str
    operations: tuple[BriefStep, ...]
    requested_by: str = ""
    change_ref: str = ""
    window: str = ""
    description: str = ""
    preflight: Mapping[str, Any] = field(default_factory=dict)
    postcheck: Mapping[str, Any] = field(default_factory=dict)
    rules: BriefRules = field(default_factory=BriefRules)
    rollback: tuple[BriefStep, ...] = ()
    success_criteria: tuple[str, ...] = ()
    must_not: tuple[str, ...] = ()
    source: Path | None = None

    # -- parsing ----------------------------------------------------------

    @classmethod
    def parse(cls, raw: Mapping[str, Any], source: Path | None = None) -> "TaskBrief":
        data = dict(raw)
        brief = _mapping(data.get("brief"), "brief")
        if not brief:
            raise ConfigError(
                "a task brief must start with a 'brief:' block containing at least "
                "id, title and host"
            )

        for required in ("id", "title", "host"):
            if not brief.get(required):
                raise ConfigError(f"brief.{required}: required")

        ops_raw = data.get("operations")
        if not ops_raw:
            raise ConfigError(
                "operations: required -- a brief with nothing to do is not a brief. "
                "List the operations to run, in order."
            )
        if isinstance(ops_raw, (str, Mapping)):
            ops_raw = [ops_raw]
        operations = tuple(
            BriefStep.parse(item, f"operations[{i}]") for i, item in enumerate(ops_raw)
        )

        rollback_raw = data.get("rollback") or []
        if isinstance(rollback_raw, Mapping):
            rollback_raw = rollback_raw.get("operations") or []
        if isinstance(rollback_raw, (str,)):
            rollback_raw = [rollback_raw]
        rollback = tuple(
            BriefStep.parse(item, f"rollback[{i}]") for i, item in enumerate(rollback_raw)
        )

        return cls(
            id=str(brief["id"]),
            title=str(brief["title"]),
            host=str(brief["host"]),
            operations=operations,
            requested_by=str(brief.get("requested_by", "")),
            change_ref=str(brief.get("change_ref", "")),
            window=str(brief.get("window", "")),
            description=str(brief.get("description", "")),
            preflight=_mapping(data.get("preflight"), "preflight"),
            postcheck=_mapping(data.get("postcheck"), "postcheck"),
            rules=BriefRules.parse(data.get("rules"), "rules"),
            rollback=rollback,
            success_criteria=tuple(
                _str_list(data.get("success_criteria"), "success_criteria")
            ),
            must_not=tuple(_str_list(data.get("must_not"), "must_not")),
            source=source,
        )

    # -- reporting --------------------------------------------------------

    @property
    def operation_ids(self) -> tuple[str, ...]:
        return tuple(step.operation for step in self.operations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "host": self.host,
            "requested_by": self.requested_by,
            "change_ref": self.change_ref,
            "window": self.window,
            "description": self.description,
            "operations": [
                {
                    "operation": s.operation,
                    "params": dict(s.params),
                    "on_failure": s.on_failure,
                    "start_at": s.start_at,
                    "only_steps": list(s.only_steps),
                    "note": s.note,
                }
                for s in self.operations
            ],
            "preflight": dict(self.preflight),
            "postcheck": dict(self.postcheck),
            "rules": self.rules.to_dict(),
            "rollback": [s.operation for s in self.rollback],
            "success_criteria": list(self.success_criteria),
            "must_not": list(self.must_not),
            "source": str(self.source) if self.source else None,
        }

    def render(self) -> str:
        """Human-readable summary, for showing an operator what they are approving."""
        lines = [
            f"{self.id}  {self.title}",
            f"  host          {self.host}",
        ]
        for label, value in (
            ("requested by", self.requested_by),
            ("change ref", self.change_ref),
            ("window", self.window),
        ):
            if value:
                lines.append(f"  {label:<13} {value}")
        if self.description:
            lines += ["", f"  {self.description.strip()}"]

        lines += ["", "  operations:"]
        for i, step in enumerate(self.operations, 1):
            params = (
                "  " + ", ".join(f"{k}={v}" for k, v in step.params.items())
                if step.params
                else ""
            )
            scope = f"  (from step {step.start_at})" if step.start_at else ""
            lines.append(f"    {i}. {step.operation}{params}{scope}  [on failure: {step.on_failure}]")
            if step.note:
                lines.append(f"       {step.note}")

        if self.success_criteria:
            lines += ["", "  done when:"]
            lines += [f"    - {c}" for c in self.success_criteria]
        if self.must_not:
            lines += ["", "  must not:"]
            lines += [f"    - {c}" for c in self.must_not]

        rules = self.rules
        lines += [
            "",
            "  rules:",
            f"    confirm destructive steps : {rules.confirm_destructive}",
            f"    stop on first failure     : {rules.stop_on_first_failure}",
            f"    reboot allowed            : {rules.reboot_allowed}",
            f"    max duration              : {rules.max_duration_minutes} min",
            f"    diagnostics allowed       : {rules.allow_diagnostic_commands}",
            f"    unlisted operations       : {rules.allow_unlisted_operations}",
        ]
        if self.rollback:
            lines += ["", f"  rollback: {', '.join(s.operation for s in self.rollback)}"]
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Loading and validation
# --------------------------------------------------------------------------


def load_brief(path: str | Path) -> TaskBrief:
    """Read and parse a brief.  Structural validation only."""
    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise ConfigError(f"task brief not found: {resolved}")
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{resolved} is not valid YAML: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{resolved}: top level must be a mapping")
    return TaskBrief.parse(raw, source=resolved)


def validate_brief(
    brief: TaskBrief, inventory: Inventory, catalog: Catalog
) -> list[str]:
    """Check a brief against the inventory and catalogue.

    Everything that can be known without connecting is checked here, so a
    malformed instruction fails before anyone types a password. Returns
    warnings; anything that would make the brief unexecutable raises.
    """
    warnings: list[str] = []
    problems: list[str] = []

    # -- the host must exist and be routable ------------------------------
    try:
        host = inventory.get(brief.host)
    except ConfigError as exc:
        raise ConfigError(f"brief '{brief.id}': {exc}") from None

    try:
        route = plan_route(inventory, brief.host)
    except Exception as exc:  # noqa: BLE001 - RouteError and friends
        raise ConfigError(
            f"brief '{brief.id}': host '{brief.host}' has no usable route.\n{exc}"
        ) from None

    # -- every operation must exist, apply, and have its parameters --------
    for index, step in enumerate(brief.operations + brief.rollback, 1):
        where = f"brief '{brief.id}' operation {index} ('{step.operation}')"
        try:
            operation = catalog.get(step.operation)
        except ConfigError as exc:
            problems.append(f"{where}: {exc}")
            continue

        if not operation.applies_to(host):
            problems.append(
                f"{where}: not permitted on host '{brief.host}'. Its host_ids are "
                f"{list(operation.host_ids) or 'unset'} and tags {list(operation.tags) or 'unset'}; "
                f"'{brief.host}' has tags {list(host.tags) or 'none'}."
            )
            continue

        declared = {p.name for p in operation.params}
        supplied = set(step.params)
        unknown = supplied - declared
        if unknown:
            problems.append(
                f"{where}: parameter(s) {sorted(unknown)} are not declared by the operation. "
                f"It accepts: {sorted(declared) or 'none'}."
            )

        missing = [
            p.name
            for p in operation.params
            if p.required and p.name not in supplied and p.default is None
            and p.name not in host.vars
        ]
        if missing:
            problems.append(f"{where}: missing required parameter(s) {missing}")

        known_steps = {s.id for s in operation.steps}
        if step.start_at and step.start_at not in known_steps:
            problems.append(
                f"{where}: start_at '{step.start_at}' is not a step of that operation. "
                f"Steps are: {', '.join(sorted(known_steps))}"
            )
        for only in step.only_steps:
            if only not in known_steps:
                problems.append(
                    f"{where}: only_steps names '{only}', which is not a step of that "
                    f"operation. Steps are: {', '.join(sorted(known_steps))}"
                )

        # -- rules must not contradict the operations listed ---------------
        if operation.destructive and not brief.rules.confirm_destructive:
            warnings.append(
                f"{where}: the operation is destructive but the brief sets "
                f"confirm_destructive: false. The operator will not be asked."
            )
        if not brief.rules.reboot_allowed and _may_reboot(operation):
            problems.append(
                f"{where}: this operation can reboot the host, but the brief sets "
                f"reboot_allowed: false. Either set it true (with the operator's "
                f"agreement) or remove the operation."
            )

    if problems:
        raise ConfigError(
            f"task brief '{brief.id}' cannot be executed:\n  - " + "\n  - ".join(problems)
        )

    # -- advisory quality checks ------------------------------------------
    if not brief.preflight.get("expect_hostname"):
        warnings.append(
            f"brief '{brief.id}': no preflight.expect_hostname. Without it, a stale or "
            f"reused port forward could point this brief at the wrong server and nothing "
            f"would notice. Set it to the host's own name."
        )
    if not brief.success_criteria:
        warnings.append(
            f"brief '{brief.id}': no success_criteria. State what 'done' looks like, or "
            f"nobody can tell whether the run achieved anything."
        )
    if not brief.change_ref:
        warnings.append(f"brief '{brief.id}': no change_ref, so this run is not traceable to a ticket.")
    if any(step.on_failure == "rollback" for step in brief.operations) and not brief.rollback:
        problems.append(
            f"brief '{brief.id}': an operation declares on_failure: rollback but no "
            f"'rollback:' block is defined."
        )
        raise ConfigError(problems[-1])

    del route
    return warnings


def _may_reboot(operation: Any) -> bool:
    """Does this operation contain a step that could restart the host?"""
    from . import safety

    for step in operation.steps:
        verdict = safety.classify(step.run)
        if verdict.reason and "reboot" in verdict.reason.lower():
            return True
    return False


def load_and_validate(
    path: str | Path, inventory: Inventory, catalog: Catalog
) -> tuple[TaskBrief, list[str]]:
    """Load a brief and validate it in one step."""
    brief = load_brief(path)
    return brief, validate_brief(brief, inventory, catalog)
