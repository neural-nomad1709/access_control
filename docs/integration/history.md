# How the integration was built

A record of the phases that added AgentLighthouse to access_control, between
2026-08-31 and 2026-09-01, and the decisions still in force. It is history, not
instructions: current commands are in [README.md](README.md).

The last commit before this work is tagged `pre-agentlighthouse-integration`.
The phases used the package names from before AgentLighthouse 0.4.0 (`al-core`,
`al-verify`, `al-governance`); see [README.md §3](README.md#3-where-agentlighthouse-comes-from).

---

## Phases

| Phase | Repository | What it delivered |
|---|---|---|
| R: context | both | Verified both codebases against the plan. Found the original packaging constraint: AgentLighthouse is a uv workspace, so an outside project had to name `al-verify` as a source as well as `al-core` |
| 0: hygiene | access_control | F-07 (`ac tunnel --port`) and F-08 (`postcheck:`) fixed; CI added; `LocalTunnel` binds exclusively on Windows so a busy port cannot be silently shared |
| AL-0: pre-work | AgentLighthouse | An approvals API and `al hitl` CLI; approvals and taint persisted across restarts (a restart can never extend a deadline); an opt-in detect-secrets scanner; the `al_core.embed` facade; receipt spec v1.1 adding `remote_exec`, `session_open`, `session_close`, `permission_request` |
| 1: evidence | access_control | The `Gatekeeper` seam (`gatekeeper.py`), the `[lighthouse]` extra and `LighthouseGatekeeper`: every canonical audit action mirrored into a signed, hash-chained ledger that `al-verify` checks offline |
| 2: enforcement | access_control | Policy before the deny-list (P1), out-of-band approval instead of an agent's `--confirm` (P2), output scanning with taint (P3), `:approve` at the operator prompt, `config/tool-policy.yaml` |
| 3: mediated agent path | access_control | `ac mcp <host>`, an MCP server over the live session; the AgentLighthouse proxy configuration; the agent permission policy in `.claude/settings.json`, pinned by a test |
| 4: governance | both | F-04 (`--max-lifetime`); per-actor tool-call budgets enforced in AgentLighthouse; a posture attestation test; the combined SIEM stream doc |

---

## Decisions still in force

| Decision | Where it shows today |
|---|---|
| The seam imports nothing from the package and defaults to a gatekeeper that changes nothing about policy, scanning or receipts | `gatekeeper.py`; the standalone product runs `LocalGatekeeper`, which only holds approvals |
| The audit sink receives records **after** redaction, and a sink failure propagates: evidence is synchronous or it is not evidence | `AuditLog.sink` |
| Local logging off does not switch governance evidence off | `AuditLog.enabled` is independent of the sink |
| Every canonical action has an explicit receipt mapping, pinned by a test | `_RECEIPT_ACTIONS` |
| A receipt's verdict is the mediation decision (`SUCCESS`/`FAILURE` → allow); the outcome stays in the JSONL | `LighthouseGatekeeper.receipt` |
| Default-deny policy applies to everyone (D4); approval instead of `--confirm` applies to agents (D3: both the operator prompt and the control plane can resolve) | `Engine._authorize`, `Engine._check_permission` |
| An approval is keyed by session, tool and the hash of the rendered commands, so it can never authorize a different command line; one approval, one run; timeout is a denial | `LighthouseGatekeeper`, `LocalGatekeeper` |
| The signing key lives under the gatekeeper's data directory, never the working directory | `keys.signing_key_path` override |
| The MCP surface strips `confirmed` and does not expose tunnels, credentials or session lifecycle | `mcp_server.EXPOSED_TOOLS` |
| A SIEM joins the two trails; no combiner process sits between the ledger and the analyst | [siem-combined-stream.md](siem-combined-stream.md) |

---

## Still open from the phases

| Item | Side |
|---|---|
| The CLI cannot switch the embedded `LighthouseGatekeeper` on | access_control — [README.md §6](README.md#6-plan) |
| No live two-process test against the real `al mcp proxy`; the acceptance test wires the same filter in one process | access_control |
| Approval resolutions made through the AgentLighthouse control plane are receipted as `mcp_tool_call`, while the operator prompt uses `permission_request` | AgentLighthouse |
| Budget windows are in memory: a mediator restart resets one window (fails open for at most a minute) | AgentLighthouse, accepted for a tripwire |
| The scanners are pattern-based: a raised bar, not guaranteed detection | AgentLighthouse |
