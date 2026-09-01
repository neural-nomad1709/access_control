# Phase 4 — Governance: Report

Date: 2026-09-01 · Branches: `wip/phase-4-governance` (both repos)
Decisions: budgets = **enforce for real** (Amit); SIEM = doc-only; attestation =
a verifying test.

## What changed

1. **F-04 absolute session lifetime** (access_control). `ac connect
   --max-lifetime <secs>` caps a session from connect, never refreshed by
   activity (0 = no ceiling, the default). The idle watchdog closes an over-age
   session and emits `session.lifetime_timeout`; `require_active` names the
   lifetime cap distinctly; `ac status` shows the remaining ceiling. Closes a
   documented gap: a continuously-driven session the idle timer alone kept open
   forever now has a bound.
2. **Per-actor tool-call budgets, actually enforced** (AgentLighthouse).
   `AgentPolicy.budgets.max_tool_calls_per_min` was schema-accepted but no code
   read it — a security field promising a rate limit it did not perform. A
   `BudgetTracker` (sliding 60s window) now enforces it at the ActionGate's
   choke point, right after policy-allow so a policy-denied call never consumes
   a slot. The N+1th call in the window fails closed with a retryable
   `BUDGET_EXCEEDED` decision, receipted like any other; an actor with no budget
   is unaffected. `ToolPolicy.budget_for` keys the limit on the actor's own
   policy, never the `default` block.
3. **Budget tripwires in the shipped policies** (access_control).
   `config/tool-policy.yaml` and `config/mcp-tool-policy.yaml` set a generous
   `max_tool_calls_per_min: 120` — a runaway-loop tripwire, not a throttle.
4. **Posture attestation covering ac operations** — a verifying test
   (access_control). Drives a `LighthouseGatekeeper` ledger with the ac action
   spread, builds the governance posture attestation for the `access-control`
   org, and proves (a) ac's receipt-v1.1 actions are counted in the artefact and
   (b) it verifies with the standalone `al-verify`, tampering detected.
   `al-governance` is a dev-group dependency (auditor tooling), never a runtime
   one.
5. **Combined-stream SIEM doc** (access_control) —
   `docs/integration/siem-combined-stream.md`: landing ac's JSONL execution
   stream and AL's ECS/MITRE receipt export in one SIEM, joined on the per-agent
   SPIFFE identity (a deterministic transform of the execution `agentId`) and
   the session id. A correlation pattern, not a new exporter.

## Test evidence

| Point | access_control | AgentLighthouse |
|---|---|---|
| Before Phase 4 | 447 passed | 687 passed, 12 skipped |
| After Phase 4 | **460 passed** (+8 F-04, +4 attestation, +1 policy) | **696 passed, 12 skipped** (+9 budget) |

## A stop-and-ask during the phase

The budget field looked like a config knob, but I verified it was **parsed and
never enforced** anywhere in AL's decision path (the existing AL test only
checked that it parsed). Documenting a tripwire value as an enforced rate limit
would have documented a control that did nothing — so I stopped and raised it.
Amit chose to make it real rather than document a hollow field; hence deliverable 2.

## What was NOT done, and why

- **No SIEM combiner process** — both streams are already SIEM-ready and the SIEM
  is the natural place to join them; a combiner would put a second writer between
  the signed ledger and the analyst for no evidence gain (documented).
- **Budget window state is in-memory** — a rate window is soft, self-healing
  state, not evidence (the receipts are the record), so it does not carry the
  persistence the HITL/taint store does. A mediator restart resets the window,
  which fails *open* for one window at most; acceptable for a tripwire, noted here.
- **AL approvals endpoint still receipts resolutions as `mcp_tool_call`** — the
  ac side uses `permission_request`; aligning AL's endpoint is a small follow-up,
  not blocking.

## Open risks

- The budget is a tripwire at 120/min, not a fine throttle; tune per identity.
- `.claude/settings.json` still lacks the 5 pre-integration OneDrive allow entries
  dropped in Phase 3 — restore on request.
