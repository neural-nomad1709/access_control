"""The MCP face of a live session — the agent's only sanctioned door.

A thin stdio JSON-RPC server wrapping the daemon protocol: every MCP tool is a
1:1 pass-through to a SessionClient method, no new capabilities. Interactive
handoff (tunnels, credentials_for) and session lifecycle (close, reload) are
deliberately NOT tools: those belong to the human operator. `confirmed` never
crosses this surface — an agent's confirmation flag carries no weight, and
approvals resolve out of band (P2).
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from access_control.errors import PermissionRequired
from access_control.mcp_server import EXPOSED_TOOLS, McpServer, serve


class RecordingClient:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses = responses or {}

    def call(self, method: str, **params: Any) -> Any:
        self.calls.append((method, params))
        if isinstance(self.responses.get(method), Exception):
            raise self.responses[method]
        return self.responses.get(method, {"ok": True, "method": method})


def rpc(method: str, params: dict | None = None, id: int | None = 1) -> dict:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if id is not None:
        msg["id"] = id
    return msg


@pytest.fixture
def server() -> tuple[McpServer, RecordingClient]:
    client = RecordingClient()
    return McpServer(client), client


class TestHandshake:
    def test_initialize_answers_with_tools_capability(self, server) -> None:
        srv, _ = server
        reply = srv.handle(rpc("initialize", {"protocolVersion": "2025-06-18"}))
        assert reply["id"] == 1
        result = reply["result"]
        assert result["protocolVersion"]
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "access-control"

    def test_initialized_notification_gets_no_reply(self, server) -> None:
        srv, _ = server
        assert srv.handle(rpc("notifications/initialized", id=None)) is None

    def test_unknown_method_is_a_clean_error(self, server) -> None:
        srv, _ = server
        reply = srv.handle(rpc("resources/list"))
        assert reply["error"]["code"] == -32601


class TestToolSurface:
    def test_the_tool_list_is_the_sanctioned_surface_only(self, server) -> None:
        srv, _ = server
        reply = srv.handle(rpc("tools/list"))
        names = {t["name"] for t in reply["result"]["tools"]}
        assert names == set(EXPOSED_TOOLS)
        assert "ac_run_operation" in names and "ac_status" in names
        # interactive handoff and lifecycle stay with the human
        for absent in ("ac_open_tunnel", "ac_close", "ac_credentials_for",
                       "ac_reload", "ac_upload", "ac_download"):
            assert absent not in names

    def test_every_tool_carries_an_input_schema(self, server) -> None:
        srv, _ = server
        for tool in srv.handle(rpc("tools/list"))["result"]["tools"]:
            assert tool["inputSchema"]["type"] == "object"
            assert isinstance(tool["description"], str) and tool["description"]


class TestToolCalls:
    def test_a_call_reaches_the_session_client(self, server) -> None:
        srv, client = server
        reply = srv.handle(rpc("tools/call", {
            "name": "ac_run_operation",
            "arguments": {"operation_id": "windows-health"},
        }))
        assert client.calls == [("run_operation", {"operation_id": "windows-health"})]
        content = reply["result"]["content"]
        assert content[0]["type"] == "text"
        assert json.loads(content[0]["text"])["method"] == "run_operation"
        assert not reply["result"].get("isError")

    def test_confirmed_is_stripped_before_it_reaches_the_wire(self, server) -> None:
        srv, client = server
        srv.handle(rpc("tools/call", {
            "name": "ac_run_operation",
            "arguments": {"operation_id": "install-package", "confirmed": True},
        }))
        assert client.calls == [("run_operation", {"operation_id": "install-package"})]

    def test_a_refusal_comes_back_as_a_tool_error_with_the_message(self) -> None:
        refusal = PermissionRequired("held for out-of-band approval (request hitl_x)")
        client = RecordingClient(responses={"run_operation": refusal})
        reply = McpServer(client).handle(rpc("tools/call", {
            "name": "ac_run_operation", "arguments": {"operation_id": "install-package"},
        }))
        result = reply["result"]
        assert result["isError"] is True
        assert "hitl_x" in result["content"][0]["text"]

    def test_an_unknown_tool_is_refused(self, server) -> None:
        srv, client = server
        reply = srv.handle(rpc("tools/call", {"name": "ac_open_tunnel", "arguments": {}}))
        assert reply["result"]["isError"] is True
        assert client.calls == []

    def test_unexpected_arguments_are_refused_not_forwarded(self, server) -> None:
        srv, client = server
        reply = srv.handle(rpc("tools/call", {
            "name": "ac_status", "arguments": {"token": "sneaky"},
        }))
        assert reply["result"]["isError"] is True
        assert client.calls == []


class TestCliCommand:
    def test_no_live_session_fails_cleanly(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from access_control import cli

        monkeypatch.setattr(cli, "attach", lambda node: None)
        result = CliRunner().invoke(cli.app, ["mcp", "win01"])
        assert result.exit_code == 1
        assert "ac connect" in result.output

    def test_serves_the_attached_session_until_eof(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from access_control import cli

        monkeypatch.setattr(cli, "attach", lambda node: RecordingClient())
        result = CliRunner().invoke(
            cli.app, ["mcp", "win01"],
            input=json.dumps(rpc("initialize", {})) + "\n",
        )
        assert result.exit_code == 0, result.output
        assert '"protocolVersion"' in result.output


class TestServeLoop:
    def test_line_in_line_out(self, server) -> None:
        srv, _ = server
        stdin = io.StringIO(
            json.dumps(rpc("initialize", {})) + "\n"
            + json.dumps(rpc("notifications/initialized", id=None)) + "\n"
            + json.dumps(rpc("tools/list", id=2)) + "\n"
        )
        stdout = io.StringIO()
        serve(srv, stdin, stdout)
        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert [r["id"] for r in replies] == [1, 2]

    def test_garbage_input_is_skipped_not_fatal(self, server) -> None:
        srv, _ = server
        stdin = io.StringIO("this is not json\n" + json.dumps(rpc("tools/list")) + "\n")
        stdout = io.StringIO()
        serve(srv, stdin, stdout)
        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert len(replies) == 1 and "result" in replies[0]

    def test_a_valid_but_non_object_frame_does_not_crash(self, server) -> None:
        srv, _ = server
        stdin = io.StringIO(
            "null\n[1,2,3]\n42\n" + json.dumps(rpc("tools/list", id=9)) + "\n")
        stdout = io.StringIO()
        serve(srv, stdin, stdout)  # must not raise
        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert [r.get("id") for r in replies] == [9]

    def test_a_non_mapping_arguments_field_is_a_tool_error_not_a_crash(self, server) -> None:
        srv, _ = server
        reply = srv.handle(rpc("tools/call", {"name": "ac_status", "arguments": "{}"}))
        assert reply["result"]["isError"] is True

    def test_a_dead_daemon_surfaces_as_a_tool_error(self) -> None:
        class DeadClient:
            def call(self, method, **params):
                raise ValueError("session response was truncated")

        reply = McpServer(DeadClient()).handle(rpc("tools/call", {
            "name": "ac_status", "arguments": {}}))
        assert reply["result"]["isError"] is True
        assert "truncated" in reply["result"]["content"][0]["text"]


class TestSchemaMatchesDaemon:
    def test_exposed_tool_schemas_cover_the_daemon_method_signature(self) -> None:
        """The hand-written schemas must not omit a daemon parameter, or a
        legitimate call is refused by the MCP surface while the daemon would
        accept it."""
        import inspect

        from access_control import daemon

        for name, spec in EXPOSED_TOOLS.items():
            handler = getattr(daemon.SessionServer, f"do_{spec.method}")
            sig = inspect.signature(handler)
            daemon_params = {
                p for p, v in sig.parameters.items()
                if p != "self" and v.kind in (v.POSITIONAL_OR_KEYWORD, v.KEYWORD_ONLY)
            }
            schema_params = set(spec.properties) | {"confirmed"}
            missing = daemon_params - schema_params
            assert not missing, f"{name} omits daemon param(s) {missing}"
