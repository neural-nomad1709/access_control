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
  serves ``ac rdp``/``ac shell``, kept off this surface (and denied to agents
  in ``.claude/settings.json`` §8.2, so neither route is open);
* session lifecycle (``close``, ``reload``) belongs to the human operator who
  typed the passwords;
* ``confirmed`` never crosses this surface — an agent's confirmation flag
  carries no weight, and approvals resolve out of band (see engine P2).
"""

from __future__ import annotations

import json
from typing import Any, NamedTuple, TextIO

from .errors import AccessControlError

PROTOCOL_VERSION = "2025-06-18"

_STR = {"type": "string"}
_INT = {"type": "integer"}
_BOOL = {"type": "boolean"}
_OBJ = {"type": "object"}


class ExposedTool(NamedTuple):
    """One MCP tool's binding to a daemon method. Named fields, not a bare
    tuple, so field-order can never silently transpose."""

    method: str
    description: str
    properties: dict[str, Any]
    required: list[str]


EXPOSED_TOOLS: dict[str, ExposedTool] = {
    "ac_status": ExposedTool(
        "status",
        "The live session's status: route, current node, counters, timers.",
        {}, [],
    ),
    "ac_preflight": ExposedTool(
        "preflight",
        "Verify the session is live and pointed at the right machine "
        "(identity, chain, round-trip, plus any checks in `spec`). `phase` "
        "tags the audit record (preflight vs postcheck).",
        {"spec": _OBJ, "phase": _STR}, [],
    ),
    "ac_operations": ExposedTool(
        "operations",
        "The catalogued operations this session may run.",
        {}, [],
    ),
    "ac_preview": ExposedTool(
        "preview",
        "Render an operation's commands with these parameters, running nothing.",
        {"operation_id": _STR, "params": _OBJ}, ["operation_id"],
    ),
    "ac_run_operation": ExposedTool(
        "run_operation",
        "Run a catalogued operation. A gated operation is held for a human's "
        "out-of-band approval; re-run once it is resolved.",
        {"operation_id": _STR, "params": _OBJ, "dry_run": _BOOL,
         "only_steps": {"type": "array", "items": _STR}, "start_at": _STR},
        ["operation_id"],
    ),
    "ac_run_command": ExposedTool(
        "run_command",
        "Run one ad-hoc command (the diagnosis escape hatch). Policy-checked, "
        "deny-listed, and held for approval when gated.",
        {"command": _STR, "shell": _STR, "timeout_s": _INT}, ["command"],
    ),
    "ac_fetch_log": ExposedTool(
        "fetch_log",
        "Tail a remote log file through the session.",
        {"path": _STR, "tail": _INT}, ["path"],
    ),
}


def _tool_descriptors() -> list[dict[str, Any]]:
    return [{
        "name": name,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": tool.properties,
            "required": tool.required,
            "additionalProperties": False,
        },
    } for name, tool in EXPOSED_TOOLS.items()]


def _tool_error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


class McpServer:
    """Dispatch MCP messages onto one attached session client."""

    def __init__(self, client: Any, *, name: str = "access-control") -> None:
        self._client = client
        self._name = name

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """One JSON-RPC message in, one reply out (None for notifications)."""
        if not isinstance(msg, dict):
            return None  # valid JSON but not a JSON-RPC object: ignore
        method = msg.get("method", "")
        if not isinstance(method, str):
            method = ""
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
        if not isinstance(params, dict):
            return _tool_error("tools/call params must be an object")
        name = params.get("name") or ""
        tool = EXPOSED_TOOLS.get(name)
        if tool is None:
            return _tool_error(f"unknown tool: {name!r} (this surface is deliberate; "
                               f"tunnels, lifecycle and credentials are operator-only)")
        raw_args = params.get("arguments") or {}
        if not isinstance(raw_args, dict):
            return _tool_error(f"arguments for {name} must be an object")
        arguments = dict(raw_args)
        # `confirmed` is silently dropped — it carries no weight here and its
        # presence must not fail an agent that cargo-cults the CLI flags.
        arguments.pop("confirmed", None)
        unexpected = [k for k in arguments if k not in tool.properties]
        if unexpected:
            return _tool_error(f"unexpected argument(s) for {name}: {unexpected}")
        missing = [k for k in tool.required if k not in arguments]
        if missing:
            return _tool_error(f"missing required argument(s) for {name}: {missing}")
        try:
            result = self._client.call(tool.method, **arguments)
            text = json.dumps(result, default=str)
        except AccessControlError as exc:
            # PermissionRequired carries the approval request id the agent
            # needs; a policy refusal carries the reason. Both are the answer.
            return _tool_error(str(exc))
        except Exception as exc:  # noqa: BLE001 — a dead daemon or a bad frame
            # is a tool error the session outlives, never a server crash.
            return _tool_error(f"session error: {exc}")
        return {
            "content": [{"type": "text", "text": text}],
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
        try:
            reply = server.handle(msg)
        except Exception as exc:  # noqa: BLE001 — one bad frame never kills the pipe
            reply = {"jsonrpc": "2.0",
                     "id": msg.get("id") if isinstance(msg, dict) else None,
                     "error": {"code": -32603, "message": f"internal error: {exc}"}}
        if reply is not None:
            stdout.write(json.dumps(reply, default=str) + "\n")
            stdout.flush()


__all__ = ["EXPOSED_TOOLS", "McpServer", "PROTOCOL_VERSION", "serve"]
