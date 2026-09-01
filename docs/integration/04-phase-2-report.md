# Phase 2 — Enforcement: Report

Date: 2026-09-01 · Branch: `wip/phase-2-enforcement` (access_control) · 3 commits
Decisions: **D3** = both approval surfaces (Amit) · **D4** = default-deny applies to
**everyone**, not only agent-attached sessions (Amit; scope: D4 covers P1 policy —
P2's HITL-instead-of-confirm remains agent-attached per the brief, and plain
NullGatekeeper installs are unchanged).

## What changed

1. **P1 authorize.** `run_command` and `run_step` consult the gatekeeper's
   identity-bound default-deny policy before the deny-list (unchanged, last line).
   Tool names: `ac_exec` and `<operation>.<step>`; argument: the rendered command;
   actor: `spiffe://access-control/agent/<agent-id>` (lowercased/sanitized to AL's
   grammar via the shared `spiffe_actor` helper).
2. **P2 approval.** For an agent-attached session, `_check_permission` ignores
   `--confirm` and files one held request per (session, operation) carrying the
   fully rendered commands. Pending refuses with the request id; approved runs once
   (the approval carries a confirm's weight for the covered steps, then is
   consumed); denied/lapsed refuses — timeout is a denial. Humans keep `--confirm`.
   Every path audited as PERMISSION_REQUEST with the request id.
   `Session.agent_attached` is set by `build_session` from `--agent-id` /
   `AC_AGENT_ID` / a Claude Code environment.
3. **P2 surfaces (D3).** `:approve` in the operator shell lists and resolves held
   requests (`:deny` refuses), resolver named and receipted as
   `permission_request` — the same `HitlGate` the AL control plane (AL-0.1) serves.
4. **P3 output scan.** Step output, `ac_exec` output, and collected diagnostics
   pass `scan_output()` before any caller sees them: secrets/PII strip on top of
   the existing redaction registry; hostile (injection) content is withheld and
   taints the session; a tainted session gates **every** operation for its
   remainder. Honest caveat: the scanners are AL's regex/heuristic baseline plus
   the opt-in detect-secrets adapter — a raised bar, not guaranteed detection.
5. **Starter policy** `config/tool-policy.yaml`: read-only catalogue steps allowed
   for an example identity, gated writes allowed-to-request, `run-command.exec`
   explicitly denied, `default: {allow: []}`. Validity + default-deny pinned by a
   test.

## Acceptance evidence (real gatekeeper + real engine)

- (a) an unallowed `ac_exec` is refused before anything reaches the wire;
- (b) `--confirm` from an agent files a held request instead of running; a human
  resolution (either surface) runs it exactly once;
- (c) a fixture log with a planted AWS key comes back redacted from collection;
- (d) an injection string in collected output taints the session and a
  previously-allowed operation then requires approval;
- every denial and resolution is a receipt `verify_chain` accepts end-to-end.

## Test evidence

| Point | access_control | AgentLighthouse |
|---|---|---|
| Before Phase 2 | 372 passed | 683 passed, 12 skipped |
| After Phase 2 | **408 passed** | **683 passed** (untouched) |

## What was NOT done, and why

- **AL-0.1 resolution receipts still use `mcp_tool_call`** on the AL side; ac-side
  resolutions (shell verb) use `permission_request`. Aligning AL's endpoint to
  `permission_request` is a small AL follow-up, noted for Phase 4 hygiene.
- **No config surface to construct LighthouseGatekeeper in the CLI/daemon** — the
  seam and behavior are complete and tested; choosing how operators enable it
  (flag/env/config file) is Phase 3 territory, where the mediated path defines who
  constructs what.
- **Expectations are evaluated on scanned output** (deliberate: no leak path via
  expectation_reason); an operation whose expectation matches secret-shaped text
  would now fail its expectation — none in the shipped catalogue does.

## Open risks

- Taint gates operations only (`_check_permission`); a tainted **human** session
  can still run allowed `ac_exec` commands with the deny-list alone — same as
  today. Widening ac_exec under taint is a candidate hardening.
- The scanners' false-negative space (regex baseline) is inherited and documented.
