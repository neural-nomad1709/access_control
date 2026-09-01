# Phase 3 — Mediated agent path: Report

Date: 2026-09-01 · Branch: `wip/phase-3-mcp` (access_control) · 2 commits

## What changed

1. **`src/access_control/mcp_server.py`** — a thin MCP server (stdio,
   newline-delimited JSON-RPC 2.0) over an attached `SessionClient`. Seven tools,
   each a 1:1 pass-through to a daemon-protocol method: `ac_status`,
   `ac_preflight`, `ac_operations`, `ac_preview`, `ac_run_operation`,
   `ac_run_command`, `ac_fetch_log`. No new capabilities. Deliberate exclusions:
   tunnels / `credentials_for` (interactive handoff — operator only), `close` /
   `reload` (session lifecycle — operator only). `confirmed` is stripped from
   every call, so an agent cannot self-approve through this surface. Refusals
   (`PermissionRequired`, policy denials) come back as MCP tool errors carrying
   the message (and the approval request id) rather than crashing.
2. **`ac mcp <host>` CLI command** — attaches to a live session and serves it on
   stdio; a clean failure (exit 1, "run ac connect") when nothing is live.
3. **AL proxy config** — `docs/integration/mcp-proxy-config.md`: how to run
   `al mcp proxy --actor … -- uv run ac mcp <host>`, with the actor-spelling and
   identity-consistency notes. (Config lands here per the routing table;
   AgentLighthouse gets no code change.)
4. **Agent permission policy** — `.claude/settings.json` now holds the
   `CLAUDE_PRODUCTION_GUARDRAILS.md` §8.2 policy: deny raw `ssh`/`plink`/`mstsc`
   and `ac connect`, deny-edit the files that define policy, ask before
   state-changing commands. Pinned by `test_agent_permission_policy.py` so code
   and doc cannot silently drift.

## Acceptance evidence (real loopback socket + real AL mediator)

`test_mcp_acceptance.py` drives an agent that can ONLY speak through AL's
`McpSession` filter, against a real `SessionServer` on a real socket:

- an agent completes a read-only catalogued operation (`echo-op`) end to end
  exclusively via the proxy, and every mediated hop (tools/list pin, the
  tools/call decision) is a receipt `verify_chain` accepts;
- a call outside policy (`ac_run_command`, or an out-of-catalogue
  `operation_id`) never reaches the server and is receipted as a denial;
- a drifted tool descriptor is refused (TOOL_DESCRIPTOR_DRIFT) and filtered from
  the agent's tool list.

## Test evidence

| Point | access_control | AgentLighthouse |
|---|---|---|
| Before Phase 3 | 419 passed | 687 passed, 12 skipped |
| After Phase 3 | **440 passed** (+12 server, +4 acceptance, +3 policy, +2 CLI) | **687 passed** (untouched) |

## What was NOT done, and why

- **`.claude/settings.json` previously held four one-off allow entries** for a
  OneDrive copy workflow from an earlier session; replacing the file with the
  §8.2 policy dropped them. Flagged to Amit — restore on request; they are
  unrelated to this repo's purpose and §8.2 defines what this file should hold.
- **No end-to-end run against the actual `al mcp proxy` subprocess** — the
  acceptance test wires ac's `McpServer` directly to AL's `McpSession` (the same
  filter the proxy pump uses), which exercises every mediation decision without a
  second process. A live two-process smoke test belongs in the final test loops.
- **`ac mcp` runs a NullGatekeeper** — mediation is the proxy's job here;
  running ac itself under a LighthouseGatekeeper as well (Phases 1–2) is the
  belt-and-braces posture and is independent of this wiring.

## Code review (2026-09-01)

8 findings; all addressed test-first (ac suite now **447 passed**):

1. **Deny list too narrow (worst)** — missed `ac shell`/`rdp`/`tunnel`, the
   unmediated `ac mcp` pipe, and general shells (pwsh/powershell/python). R-11's
   "only door" was false. Deny list expanded; pinned by test.
2. **Engine honored `confirmed` for agents on not_governed** — the no-self-approval
   invariant lived only in the MCP wrapper's `confirmed`-strip. The engine now
   REFUSES a gated op or exec for an agent-attached session with no governance
   plane, `--confirm` or not.
3. **`ac mcp` unbucketed in settings.json** — now denied (the unmediated pipe must
   not be an agent's shortcut around the proxy).
4. **No top-level exception guard** — a dead daemon or a non-object frame crashed
   the server; both are tool errors / skips now.
5. **`ac_preflight` missing `phase`** — added; a schema-drift test now asserts every
   tool covers its daemon method's parameters.
6. **Acceptance suite wrote real session descriptors** — `AC_DATA_DIR` isolated.
7. **stdin/stdout not UTF-8/LF** — `ac mcp` reconfigures both.
8. **Proxy-config doc pointed at the wrong policy file** — shipped
   `config/mcp-tool-policy.yaml` (ac_* names) + `config/al-mcp-proxy.yaml`; doc
   corrected.

## Open risks

- The session protocol is a convenience boundary, not a privilege boundary (any
  process as the same user can drive the socket). The MCP server inherits that:
  it is the *sanctioned* door, and the §8.2 policy denying raw shells is what
  makes it the *only* door — the policy and the proxy are one control together,
  neither sufficient alone.
