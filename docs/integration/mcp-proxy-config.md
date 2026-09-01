# Running the ac MCP server behind AgentLighthouse's proxy

This is the mediated agent path (Phase 3): the agent reaches `ac` **only**
through AgentLighthouse, which pins the tool surface, applies per-identity
policy, scans results, and signs a receipt per call. It closes R-11 in
practice — combined with the agent permission policy in
[`CLAUDE_PRODUCTION_GUARDRAILS.md` §8.2](../CLAUDE_PRODUCTION_GUARDRAILS.md)
(deny raw `ssh`/`plink`/`mstsc` and `ac connect`), pinned in
`.claude/settings.json`.

## The pieces

```
agent ──stdio JSON-RPC──▶ al mcp proxy ──stdio──▶ uv run ac mcp <host> ──socket──▶ ac session
                              │                         │
                     pins + policy + scan        thin 1:1 wrapper of the
                     + receipt per call          daemon protocol (no new caps)
```

- **`ac mcp <host>`** — the thin MCP server (`src/access_control/mcp_server.py`).
  It attaches to a live session by host id and exposes the agent-facing daemon
  methods as MCP tools (`ac_status`, `ac_preflight`, `ac_operations`,
  `ac_preview`, `ac_run_operation`, `ac_run_command`, `ac_fetch_log`). Tunnels,
  `credentials_for`, `close` and `reload` are deliberately absent — operator
  only. `confirmed` is stripped from every call.
- **`al mcp proxy`** — AgentLighthouse's mediator. It runs `ac mcp` as its
  upstream subprocess, pins the advertised descriptors on first sight (drift is
  refused thereafter), authorizes each `tools/call` against the identity's tool
  policy, scans results, and records a signed receipt per decision.

## Prerequisites

1. The operator opens the session in their own terminal (this is where
   passwords are typed — the agent never sees one):

   ```
   uv run ac connect prod-app01 --agent-id claude/j.doe/INC0001234 \
       --ops windows-health,collect-diagnostics --idle-timeout 1800
   ```

   `--agent-id` pins the SPIFFE identity the policy names; `--ops` scopes the
   catalogue. The session marks itself agent-attached, so gated work resolves
   out of band (P2), never via a flag.

2. A tool policy for that identity, named for the **MCP tools** the proxy sees
   (`ac_status`, `ac_run_operation`, …), in `config/mcp-tool-policy.yaml`. This
   is a different file from `config/tool-policy.yaml`, whose names are catalogue
   steps (`<operation>.<step>`, `ac_exec`) for the embedded gatekeeper inside
   ac. The proxy reads its policy through its AL `--config`'s
   `policy.tool_policy_path`, so `config/al-mcp-proxy.yaml` wires the two
   together.

## Launch

```
export AL_ADMIN_API_TOKEN=…    # the proxy's Runtime needs it; never in a file
al mcp proxy \
    --actor spiffe://access-control/agent/claude-j-doe-inc0001234 \
    --session prod-app01 \
    --config config/al-mcp-proxy.yaml \
    -- uv run ac mcp prod-app01
```

`config/al-mcp-proxy.yaml` sets `policy.tool_policy_path:
config/mcp-tool-policy.yaml` — edit **that** file to scope which `ac_*` tools
(and which `operation_id` values) the identity may reach. Pointing `--config`
at a plain AL config with no `policy` section falls back to AL's own default
deny-all, and every agent call is blocked.

The agent connects to `al mcp proxy` on stdio. Every hop — the tools/list pin,
each tools/call decision, each result scan — is a receipt in AL's ledger,
verifiable offline with `al-verify`.

## Notes

- **Actor spelling.** The proxy's `--actor` must match the SPIFFE id ac's own
  receipts use: `spiffe://access-control/agent/<agent-id>`, lowercased and
  sanitized to `[a-z0-9._-]` (see `gatekeeper.spiffe_actor`). Keep the policy
  file, the `--actor`, and `--agent-id` consistent, or the identity denies.
- **Two planes, one workload.** `ac mcp` runs a `NullGatekeeper` by default (it
  only wraps the socket); the governance decisions are the proxy's job. Running
  ac *itself* under a `LighthouseGatekeeper` as well (Phases 1–2) is the
  belt-and-braces posture: mediation at the door, enforcement at the engine.
- **Read-only first.** The Phase 3 acceptance target is a read-only catalogued
  operation end to end. Grant write operations in the policy only once the
  approval flow is exercised for that identity.
