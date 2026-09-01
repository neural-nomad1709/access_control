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

2. A tool policy for that identity (see `config/tool-policy.yaml`). The MCP
   tool names are `ac_<method>` — e.g. `ac_run_operation` with an
   `operation_id` `allow_values` constraint scoping which operations the agent
   may run through the proxy.

## Launch

```
al mcp proxy \
    --actor spiffe://access-control/agent/claude-j-doe-inc0001234 \
    --session prod-app01 \
    --config configs/balanced.yaml \
    -- uv run ac mcp prod-app01
```

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
