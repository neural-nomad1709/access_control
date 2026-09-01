# Phase 1 — Evidence: Report

Date: 2026-09-01 · Branch: `wip/phase-1-evidence` (access_control) · 2 commits

## What changed

1. **`gatekeeper.py`** — the `Gatekeeper` Protocol (authorize / request_approval /
   scan_output / receipt) with its types (`GateDecision`, `ApprovalTicket`,
   `ScanVerdict`) and `NullGatekeeper`, the default and compatibility contract:
   everything allowed, output untouched, receipts dropped, zero new dependencies.
   The module imports nothing from the package, so the dependency direction
   (`cli → daemon → engine → session → transport`) is untouched.
2. **Seam wiring** — `Engine(session, gatekeeper=None)` (defaults to
   `NullGatekeeper`); `AuditLog` gained an optional `sink` invoked with every
   canonical action record **post-redaction** (no secret can reach an external
   ledger); `build_session(..., gatekeeper=None)` attaches `gatekeeper.receipt` as
   that sink. A sink failure propagates — evidence is synchronous or it is not
   evidence.
3. **`[lighthouse]` extra** — `al-core` as an editable path source on the sibling
   clone, plus an explicit `al-verify` source (AL's uv-workspace source for it is
   invisible to an external consumer). Editable because a wheel built from the
   path drops `al_core.keys`: AL's `.gitignore` has a `keys` pattern (signing-key
   material) and hatchling excludes VCS-ignored paths.
4. **`LighthouseGatekeeper`** — embeds an AL Runtime via the `al_core.embed`
   facade. `receipt()` maps canonical actions into receipt-v1.1's closed
   vocabulary (session-establishment → `session_open`; execution / transfer /
   collection → `remote_exec`; `PERMISSION_REQUEST` → `permission_request`;
   `SESSION_END` → `session_close`), the audit result to the mediation verdict
   (SUCCESS/FAILURE → allow — the verdict is the mediation decision, the outcome
   stays in the JSONL; BLOCKED → block; PENDING → ask), the original action
   preserved in the receipt target (`"SSH_CONNECT:bastion1"`), actor as
   `spiffe://access-control/agent/<agentId>`, session as the ac session id.
   Decision methods remain Null-equivalent until Phase 2.

## Acceptance evidence

- A full fake-SSH e2e session (real `sshfake` servers: bastion key+password →
  target, `uname -a` through the Engine, close) produces a ledger that
  `al_verify.verify_chain` — the exact code `al-verify` runs — validates end to
  end (`test_lighthouse_gatekeeper.py::TestEndToEndOverFakeSSH`).
- Tampering with one record's target makes verification raise
  (`TestLedgerIntegrity::test_tampering_with_one_record_fails_verification`).
- With `NullGatekeeper` (and on a plain install, where the lighthouse tests
  importorskip), behaviour is unchanged: the whole pre-existing suite passes
  untouched, and the JSONL trail is byte-identical in form (asserted in the e2e).

## Test evidence

| Point | access_control | AgentLighthouse |
|---|---|---|
| Before Phase 1 | 351 passed | 683 passed, 12 skipped |
| After Phase 1 | **367 passed** (+9 seam, +7 lighthouse) | **683 passed** (untouched) |

## What was NOT done, and why

- **No enforcement** — P1 authorize / P2 approval / P3 output-scan call sites in
  `engine.py` are Phase 2; `LighthouseGatekeeper`'s decision methods deliberately
  mirror `NullGatekeeper` until then.
- **No daemon CLI flag to select the gatekeeper** — nothing constructs
  `LighthouseGatekeeper` in production paths yet; how it is enabled (env/config)
  lands with Phase 2, when it starts making decisions worth configuring.
- **al-verify CLI not shelled out in tests** — the tests call
  `al_verify.verify_chain`, the same function the CLI wraps.

## Open risks

- CI (`uv sync --frozen`) on a checkout without the sibling AgentLighthouse clone:
  the lockfile now records editable path sources. `uv sync` without the extra
  should not touch them, but this is unverified until the next CI run — if it
  breaks, CI needs either a sibling checkout step or `--no-sources`.
- The receipt `verdict` for FAILURE results is `allow` by design (mediation
  verdict, not outcome); an auditor reading only receipts sees permissions, not
  operational success — the target string and the JSONL carry the outcome.
