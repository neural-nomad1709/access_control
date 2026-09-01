"""The repo's agent permission policy IS the R-11 mitigation's other half.

The mediated MCP path only helps if the agent cannot walk around it: a raw
ssh/plink/mstsc or an `ac connect` from the agent's shell bypasses every gate.
This pins .claude/settings.json to the policy CLAUDE_PRODUCTION_GUARDRAILS.md
§8.2 documents, so the two cannot drift apart silently.
"""

from __future__ import annotations

import json
from pathlib import Path

SETTINGS = Path(__file__).parents[1] / ".claude" / "settings.json"


def _policy() -> dict:
    return json.loads(SETTINGS.read_text(encoding="utf-8"))["permissions"]


def test_raw_transports_and_connect_are_denied() -> None:
    deny = _policy()["deny"]
    for pattern in ("Bash(ssh*)", "Bash(plink*)", "Bash(mstsc*)",
                    "Bash(uv run ac connect*)"):
        assert pattern in deny, f"§8.2 requires denying {pattern}"


def test_the_policy_surface_itself_is_deny_edited() -> None:
    deny = _policy()["deny"]
    for guarded in ("Edit(config/operations.yaml)", "Edit(config/inventory.yaml)",
                    "Edit(src/access_control/safety.py)"):
        assert guarded in deny, (
            "the files that DEFINE policy must not be agent-editable"
        )


def test_state_changing_commands_ask_first() -> None:
    ask = _policy()["ask"]
    for pattern in ("Bash(uv run ac run*)", "Bash(uv run ac exec*)",
                    "Bash(uv run ac brief run*)"):
        assert pattern in ask
