"""Network context, agent identity, and logging configuration.

Three things that were previously implicit and now are not:

**Network context** -- environment, datacenter, network zone and owner, attached
to every node.  The route resolver uses it to enforce compliance boundaries: a
QA bastion must not become a path into PROD just because the graph happens to
connect.

**Agent identity** -- a per-run ``AGT-<date>-<suffix>`` and a per-session
``SES-<suffix>``.  A single static agent id makes concurrent runs
indistinguishable in the audit trail, which is exactly when you most need to
tell them apart.  The suffixes are random rather than counted: uniqueness must
hold across concurrent processes, and a shared counter file cannot promise that
without cross-process locking -- randomness needs no coordination at all.

**Logging configuration** -- location, level and retention, declared in config
rather than hardcoded, so logs can be pointed at a collected directory for SIEM
ingestion.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .paths import ensure_dir

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
DEFAULT_RETENTION_DAYS = 30


# --------------------------------------------------------------------------
# Network context
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkContext:
    """Where a node sits, for routing and compliance decisions."""

    environment: str = ""
    datacenter: str = ""
    network_zone: str = ""
    owner: str = ""
    extra: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: Any) -> "NetworkContext":
        if not raw:
            return cls()
        data = dict(raw)
        known = {"environment", "datacenter", "network_zone", "networkZone", "owner"}
        return cls(
            environment=str(data.get("environment", "")),
            datacenter=str(data.get("datacenter", "")),
            # Accept the camelCase spelling from the reference config too.
            network_zone=str(data.get("network_zone", data.get("networkZone", ""))),
            owner=str(data.get("owner", "")),
            extra={k: str(v) for k, v in data.items() if k not in known},
        )

    def describe(self) -> str:
        parts = [
            f"{name}={value}"
            for name, value in (
                ("env", self.environment),
                ("dc", self.datacenter),
                ("zone", self.network_zone),
                ("owner", self.owner),
            )
            if value
        ]
        return ", ".join(parts) or "(no context)"

    def to_dict(self) -> dict[str, str]:
        data = {
            "environment": self.environment,
            "datacenter": self.datacenter,
            "network_zone": self.network_zone,
            "owner": self.owner,
        }
        data.update(self.extra)
        return {k: v for k, v in data.items() if v}

    def conflicts_with(self, other: "NetworkContext") -> str | None:
        """Report an environment mismatch, or None if traversal is acceptable.

        Only ``environment`` is treated as a hard boundary. Datacenter and zone
        are recorded for audit and for humans to reason about, but crossing them
        is routine (a bastion in one datacenter reaching a host in another is
        the normal case); crossing an environment boundary is not.
        """
        if not self.environment or not other.environment:
            return None
        if self.environment.upper() != other.environment.upper():
            return f"{self.environment} -> {other.environment}"
        return None


# --------------------------------------------------------------------------
# Agent identity
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentIdentity:
    """Who is acting, and under which session.

    ``agent_id`` identifies the running agent instance (``AGT-20260812-3f9a1c``);
    ``session_id`` identifies one authenticated path (``SES-3f9a1c``).  Both
    appear on every audit record so concurrent runs stay separable.
    """

    agent_id: str
    session_id: str
    #: Sortable id used for log filenames; the human-facing ids are not.
    trace_id: str

    @classmethod
    def create(
        cls,
        *,
        prefix: str = "AGT",
        session_prefix: str = "SES",
        agent_id: str | None = None,
    ) -> "AgentIdentity":
        explicit = agent_id or os.environ.get("AC_AGENT_ID")
        stamp = datetime.now(timezone.utc)
        day = stamp.strftime("%Y%m%d")

        # One random suffix ties the session's ids together.  Random, not a
        # persisted counter: ten sessions launched in the same second by ten
        # independent processes must never share an id, and the log file is
        # named by trace_id -- a collision would interleave two audit trails.
        suffix = uuid.uuid4().hex[:6]
        resolved_agent = explicit or f"{prefix}-{day}-{suffix}"
        session = f"{session_prefix}-{suffix}"
        trace = f"{stamp.strftime('%Y%m%dT%H%M%SZ')}-{suffix}"
        return cls(agent_id=resolved_agent, session_id=session, trace_id=trace)

    def to_dict(self) -> dict[str, str]:
        return {
            "agentId": self.agent_id,
            "sessionId": self.session_id,
            "traceId": self.trace_id,
        }


# --------------------------------------------------------------------------
# Logging configuration
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LoggingConfig:
    """Where the audit trail is written and how long it is kept."""

    enabled: bool = True
    path: Path | None = None
    retention_days: int = DEFAULT_RETENTION_DAYS
    level: str = "INFO"

    @classmethod
    def parse(cls, raw: Any) -> "LoggingConfig":
        from .errors import ConfigError

        if not raw:
            return cls()
        data = dict(raw)
        level = str(data.get("level", "INFO")).upper()
        if level not in LOG_LEVELS:
            raise ConfigError(
                f"logging.level: '{level}' is not one of {list(LOG_LEVELS)}"
            )
        raw_path = data.get("path")
        retention = int(data.get("retention_days", data.get("retentionDays", DEFAULT_RETENTION_DAYS)))
        if retention < 0:
            raise ConfigError("logging.retention_days must be zero or positive (0 = keep forever)")
        return cls(
            enabled=bool(data.get("enabled", True)),
            path=Path(os.path.expandvars(str(raw_path))).expanduser() if raw_path else None,
            retention_days=retention,
            level=level,
        )

    def resolve_directory(self) -> Path:
        """The directory to write to.

        Precedence: ``AC_LOG_DIR`` env override, then the configured path, then
        the per-user default outside the repository.
        """
        override = os.environ.get("AC_LOG_DIR")
        if override:
            return ensure_dir(Path(override).expanduser())
        if self.path is not None:
            return ensure_dir(self.path)
        from .paths import log_dir

        return ensure_dir(log_dir())

    def prune(self, directory: Path | None = None) -> list[str]:
        """Delete trails older than ``retention_days``.  Returns what was removed.

        Never raises: a failure to prune must not stop a session from starting.
        """
        if self.retention_days <= 0:
            return []
        base = directory or self.resolve_directory()
        if not base.exists():
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        removed: list[str] = []
        for pattern in ("*.jsonl", "*.md"):
            for candidate in base.glob(pattern):
                try:
                    modified = datetime.fromtimestamp(
                        candidate.stat().st_mtime, tz=timezone.utc
                    )
                    if modified < cutoff:
                        candidate.unlink()
                        removed.append(candidate.name)
                except OSError:
                    continue
        return removed

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "path": str(self.resolve_directory()),
            "retention_days": self.retention_days,
            "level": self.level,
        }


# --------------------------------------------------------------------------
# Domain-qualified identities
# --------------------------------------------------------------------------

_ALREADY_QUALIFIED = re.compile(r"^[^\\@]+[\\@].+$")

#: ``DOMAIN\user`` -- a NetBIOS domain, directly comparable to a `domain:` field.
_DOWN_LEVEL = re.compile(r"^(?P<domain>[^\\@]+)\\(?P<user>.+)$")
#: ``user@dns.suffix`` -- a UPN. Its first label is the usual NetBIOS name.
_UPN = re.compile(r"^(?P<user>[^\\@]+)@(?P<suffix>.+)$")


def embedded_domain(username: str | None) -> str | None:
    """The domain carried inside a username, or None if it carries none.

    ``CORP\\me`` -> ``CORP``.  ``me@corp.example.com`` -> ``corp``, since the
    first DNS label is conventionally the NetBIOS name.
    """
    if not username:
        return None
    down_level = _DOWN_LEVEL.match(username)
    if down_level:
        return down_level.group("domain")
    upn = _UPN.match(username)
    if upn:
        return upn.group("suffix").split(".", 1)[0]
    return None


def bare_username(username: str | None) -> str | None:
    """The username with any carried domain stripped off.

    ``CORP\\me`` and ``me@corp.net`` both yield ``me`` -- the halves sit on
    opposite sides of the separator in the two forms, which is why this is not a
    plain split.
    """
    if not username:
        return username
    down_level = _DOWN_LEVEL.match(username)
    if down_level:
        return down_level.group("user")
    upn = _UPN.match(username)
    if upn:
        return upn.group("user")
    return username


def qualify_username(username: str | None, domain: str | None) -> str | None:
    """Return ``DOMAIN\\user`` when a domain is configured.

    Windows authentication against a domain-joined host fails with a bare
    username, and the failure looks like a wrong password rather than a wrong
    identity -- which sends people resetting credentials that were fine. If the
    username already carries a domain (``CORP\\me`` or ``me@corp.net``) it is
    left alone.
    """
    if not username:
        return username
    if not domain:
        return username
    if _ALREADY_QUALIFIED.match(username):
        return username
    return f"{domain}\\{username}"
