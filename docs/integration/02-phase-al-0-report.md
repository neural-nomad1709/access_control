# Phase AL-0 — AgentLighthouse Pre-work: Report

Date: 2026-08-31 · Branch: `wip/phase-al-0` (AgentLighthouse) · 5 commits

## What changed

1. **AL-0.1 Approvals surface.** `GET /api/approvals` (pending with actor/tool/age/
   remaining) and `POST /api/approvals/{id}` (allow|deny) behind the pre-existing
   `approve` capability (admin + operator roles). The resolving actor is recorded on
   the request and in one signed receipt per resolution, verifiable via
   `/api/verify/{seq}`. New `al hitl list|approve|deny` CLI verbs — HTTP clients of
   the running control plane, since pending approvals live in the serving process.
   Semantics preserved exactly: a lapsed request is never listed and cannot be
   resolved; timeout remains a denial. `HitlGate` gained `resolved_by`, `age_s`,
   `remaining_s`; `approve/deny` accept an optional `by=`.
2. **AL-0.2 Persistence.** `CapabilityStore` (SQLite/WAL, next to the ledger mirror)
   for approvals and taint marks; `HitlGate`/`TaintTracker` take an optional store
   and rehydrate on boot; the Runtime wires it in. Deadlines: the gates use a
   monotonic clock, so the store keeps wall-clock submission time and rehydration
   re-anchors preserving elapsed age — a restart can never extend a deadline. Taint
   rehydration closes the documented fail-open (a tainted session no longer comes
   back clean).
3. **AL-0.3 detect-secrets adapter.** `DetectSecretsScanner` behind the `Scanner`
   Protocol with a curated high-signal plugin list (AWS/GitHub/Slack/Stripe/JWT/
   private-key/... detectors; the noisy generic-entropy plugins deliberately
   excluded — AL has its own tuned EntropyScanner). Findings carry redaction class +
   span only, never plaintext; an unlocatable hit blocks instead of part-redacting.
   Fail-closed matrix proven for this adapter (crash → SCANNER_FAILED, hang →
   SCANNER_TIMEOUT). Opt-in: `al-core[scanners]` extra + `scanner.detect_secrets.
   enabled: true`; enabling without the package refuses at boot. README's "What This
   Does Not Do" updated to say exactly what shipped (still pattern matching, not ML).
4. **AL-0.4 Embedding facade.** `al_core.embed` re-exports the embedder contract
   (Runtime — itself the factory — gates, decision/result types, ACTIONS/VERDICTS);
   a contract test imports only that surface and drives authorize → scan → record.
5. **AL-0.5 Receipt spec v1.1 (D2, approved by Amit: extend).** `remote_exec`,
   `session_open`, `session_close`, `permission_request` added to the producer
   Literal, the JSON schema, and the spec text (a test pins the three equal).
   al-verify needed **no change**: verification is over canonical bytes + signature,
   so the vocabulary never enters the crypto — every pre-existing receipt still
   verifies, proven by tests over all eleven v1.0 actions and a mixed chain.

## Test evidence

| Point | AgentLighthouse | access_control |
|---|---|---|
| Before AL-0 | 632 passed, 12 skipped | 351 passed |
| After AL-0 | **674 passed, 12 skipped** (+42) | **351 passed** (untouched) |

## What was NOT done, and why

- **No dashboard approvals panel** — the brief offered "a dashboard panel or CLI
  verbs"; the CLI verbs are less code and serve the same gate. A React panel can
  follow once the approvals API is exercised by Phase 2. (Observability upgrade
  deferred by Amit.)
- **No Presidio / LLM Guard adapters** — out of AL-0 scope; the seam is proven.
- **Resolution receipts use `mcp_tool_call`** (target `hitl:<request_id>`) — written
  before v1.1 landed. Migrating them to `permission_request` is a candidate for
  Phase 2 wiring, noted as an open item.
- Amit's uncommitted `README.md` trademark-line edit and untracked `paper/` remain
  untouched in the working tree, per instruction.

## Open risks

- The `al hitl` CLI needs the control plane running; there is no offline fallback
  (deliberate — the state lives in that process; AL-0.2 persistence covers restarts,
  not out-of-band mutation).
- detect-secrets adds per-line scanning cost when enabled; unmeasured here (no
  benchmark claims per house rules).
