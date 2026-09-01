"""The MCP face of a live session — the agent's only sanctioned door (R-11).

A thin server speaking MCP's stdio transport (newline-delimited JSON-RPC 2.0)
over an attached :class:`~.daemon.SessionClient`. Meant to run behind
AgentLighthouse's MCP proxy (`al mcp proxy -- ac mcp <host>`), which pins the
tool descriptors, authorizes each call against per-identity policy, scans
results, and signs a receipt per hop — so the agent reaches ac only through a
reviewed, mediated surface.

Every tool is a 1:1 pass-through to a daemon-protocol method; there are no new
capabilities. Three deliberate exclusions:

* interactive handoff (``open_tunnel``/``close_tunnel``/``credentials_for``)
  serves ``ac rdp``/``ac shell``, which the agent permission policy denies to
  agents outright;
* session lifecycle (``close``, ``reload``) belongs to the human operator who
  typed the passwords;
* ``confirmed`` never crosses this surface — an agent's confirmation flag
  carries no weight, and approvals resolve out of band (see engine P2).
"""

from __future__ import annotations

import json
from typing import Any, TextIO

from .errors import AccessControlError

PROTOCOL_VERSION = "2025-06-18"

_STR = {"type": "string"}
_INT = {"type": "integer"}
_BOOL = {"type": "boolean"}
_OBJ = {"type": "object"}

#: tool name -> (daemon method, description, properties, required)
EXPOSED_TOOLS: dict[str, tuple[str, str, dict[str, Any], list[str]]] = {
    "ac_status": (
        "status",
        "The live session's status: route, current node, counters, timers.",
        {}, [],
    ),
    "ac_preflight": (
        "preflight",
        "Verify the session is live and pointed at the right machine "
        "(identity, chain, round-trip, plus any checks in `spec`).",
        {"spec": _OBJ}, [],
    ),
    "ac_operations": (
        "operations",
        "The catalogued operations this session may run.",
        {}, [],
    ),
    "ac_preview": (
        "preview",
        "Render an operation's commands with these parameters, running nothing.",
        {"operation_id": _STR, "params": _OBJ}, ["operation_id"],
    ),
    "ac_run_operation": (
        "run_operation",
        "Run a catalogued operation. A gated operation is held for a human's "
        "out-of-band approval; re-run once it is resolved.",
        {"operation_id": _STR, "params": _OBJ, "dry_run": _BOOL,
         "only_steps": {"type": "array", "items": _STR}, "start_at": _STR},
        ["operation_id"],
    ),
    "ac_run_command": (
        "run_command",
        "Run one ad-hoc command (the diagnosis escape hatch). Policy-checked, "
        "deny-listed, and held for approval when gated.",
        {"command": _STR, "shell": _STR, "timeout_s": _INT}, ["command"],
    ),
    "ac_fetch_log": (
        "fetch_log",
        "Tail a remote log file through the session.",
        {"path": _STR, "tail": _INT}, ["path"],
    ),
}


def _tool_descriptors() -> list[dict[str, Any]]:
    return [{
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    } for name, (_, description, properties, required) in EXPOSED_TOOLS.items()]


def _tool_error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


class McpServer:
    """Dispatch MCP messages onto one attached session client."""

    def __init__(self, client: Any, *, name: str = "access-control") -> None:
        self._client = client
        self._name = name

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """One JSON-RPC message in, one reply out (None for notifications)."""
        method = msg.get("method", "")
        rid = msg.get("id")
        if method.startswith("notifications/"):
            return None
        if method == "initialize":
            return self._reply(rid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self._name, "version": "1"},
            })
        if method == "tools/list":
            return self._reply(rid, {"tools": _tool_descriptors()})
        if method == "tools/call":
            return self._reply(rid, self._call(msg.get("params") or {}))
        if rid is None:
            return None  # unknown notification: ignore
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"method not supported: {method}"}}

    def _call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name") or ""
        exposed = EXPOSED_TOOLS.get(name)
        if exposed is None:
            return _tool_error(f"unknown tool: {name!r} (this surface is deliberate; "
                               f"tunnels, lifecycle and credentials are operator-only)")
        method, _, properties, required = exposed
        arguments = dict(params.get("arguments") or {})
        # `confirmed` is silently dropped — it carries no weight here and its
        # presence must not fail an agent that cargo-cults the CLI flags.
        arguments.pop("confirmed", None)
        unexpected = [k for k in arguments if k not in properties]
        if unexpected:
            return _tool_error(f"unexpected argument(s) for {name}: {unexpected}")
        missing = [k for k in required if k not in arguments]
        if missing:
            return _tool_error(f"missing required argument(s) for {name}: {missing}")
        try:
            result = self._client.call(method, **arguments)
        except AccessControlError as exc:
            # PermissionRequired carries the approval request id the agent
            # needs; a policy refusal carries the reason. Both are the answer,
            # not a crash.
            return _tool_error(str(exc))
        return {
            "content": [{"type": "text", "text": json.dumps(result, default=str)}],
            "isError": False,
        }

    def _reply(self, rid: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "result": result}


def serve(server: McpServer, stdin: TextIO, stdout: TextIO) -> None:
    """Pump newline-delimited JSON-RPC until stdin closes.

    Garbage lines are skipped rather than fatal: the session outlives a
    client's framing bug, and the daemon socket already enforces its own
    limits underneath.
    """
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reply = server.handle(msg)
        if reply is not None:
            stdout.write(json.dumps(reply, default=str) + "\n")
            stdout.flush()


__all__ = ["EXPOSED_TOOLS", "McpServer", "PROTOCOL_VERSION", "serve"]
