"""F-12: every canonical action the code emits is listed in ``audit.ACTIONS``.

A SIEM filter built from ``ACTIONS`` silently misses any name that is emitted
but not listed, so the list is checked against the source rather than trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

from access_control import audit

SOURCE = Path(audit.__file__).parent
EMITTED = re.compile(r"\.action\(\s*\"([A-Z_]+)\"")


def emitted_actions() -> set[str]:
    names: set[str] = set()
    for path in SOURCE.rglob("*.py"):
        names.update(EMITTED.findall(path.read_text(encoding="utf-8")))
    return names


def test_the_scan_finds_the_actions_it_should() -> None:
    found = emitted_actions()
    assert {"TUNNEL_OPEN", "PREFLIGHT", "COMMAND", "RDP_LAUNCH"} <= found


def test_every_emitted_action_is_canonical() -> None:
    missing = emitted_actions() - set(audit.ACTIONS)
    assert not missing, f"emitted but absent from audit.ACTIONS: {sorted(missing)}"
