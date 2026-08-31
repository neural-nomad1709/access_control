# Phase R — Context Load: Verification Report

Date: 2026-08-31 · Verified against both working trees at:
access_control `dd1fc82` (main), AgentLighthouse `2105b76` (main, dirty: modified README.md + untracked paper/, left untouched per Amit).

## Test evidence

| Repo | Result |
|---|---|
| access_control | 341 passed, 21.09s |
| AgentLighthouse | 632 passed, 12 skipped (Linux-only nftables/POSIX-mode, live-Postgres mirror), 58.63s |

Both green; no Phase 0 test-fixing work exists.

## Confirmed as the brief states

- **access_control**: dependency direction `cli → daemon → engine → session → transport` (ARCHITECTURE.md:97); `Engine.__init__(self, session)` with no gatekeeper param (engine.py:255); `_check_permission` (engine.py:620) honours `confirmed` flag and raises `PermissionRequired` with rendered commands; `run_command` (engine.py:483) calls `safety.check` first; `collect` (engine.py:523); two-tier BLOCKED/CONFIRM/ALLOWED first-match-wins regex in safety.py; fsynced JSONL audit (audit.py:192) with 16 canonical actions; `AgentIdentity(agent_id, session_id, trace_id)` (context.py:112); operator_shell has no `:approve`; no gatekeeper.py, no reference to AL anywhere; no `[lighthouse]` extra; no CI, no lint/type tooling configured; `tests/sshfake.py` is a real in-process Paramiko server (not a mock); session-protocol.md and CLAUDE_PRODUCTION_GUARDRAILS.md §8.2 both exist.
- **F-07 and F-08 still unfixed**: `ac tunnel --port` declared (cli.py:1324) but never passed to `open_tunnel` (cli.py:1366, 1375); `postcheck:` parsed in brief.py (160/214/251) with no execution site in src/.
- **F-04 unfixed**: idle timeout only, no absolute session lifetime.
- **AgentLighthouse**: `HitlGate` has submit/approve/deny/pending with timeout-is-denial (hitl.py:107-109); `ActionGate.resume()` (gate.py:218); `HitlGate._pending` and `TaintTracker._sessions` are in-memory dicts (hitl.py:73, taint.py:41) — restart loses pending approvals (fail-closed) and taint (fail-open); `ToolPolicy` default-deny per SPIFFE id with arg constraints (policy.py:147); `Scanner` is a runtime-checkable Protocol with a fail-closed matrix in `ContentGate` (crash → SCANNER_FAILED block, deadline → SCANNER_TIMEOUT, unknown verdicts rank as block); implementations are regex/heuristics only, no detect-secrets adapter; no `al_core.embed` facade; no SQLite tables for approvals/taint (db.py has events/identities/quotas only); app.py has **no** /api/approvals (endpoints: healthz, session, killswitch GET/POST, summary, receipts, chain, search, trends, receipts/{seq}, verify/{seq}, dashboard); CLI has no `hitl` verb (approve exists only under `skill` and `learn`); receipt-v1 closed vocabulary of 11 actions (`http_forward, fetch, llm_call, mcp_tool_call, mcp_tool_result, memory_read, memory_write, skill_load, a2a_message, config_change, killswitch`), Ed25519 + SHA-256 hash chain over RFC 8785 JCS; `al-verify` standalone with sole dep `cryptography>=43`; substantial MCP mediation already shipped (mediator/session/proxy/descriptors/chain).

## Differs from the brief

1. **Phase 0.1 is already done upstream.** `.gitignore` no longer has `*credential*` (narrowed to `credentials.json` / `*credentials.y*ml` / `*credentials.txt`); `src/access_control/credentials.py` is tracked; commit `dd1fc82` updated STATUS.md accordingly. Phase 0 reduces to: CI in both repos + F-07 + F-08.
2. **Recommended-work list has 18 items**, not 17 (item 18: change-management integration validating `change_ref`).
3. **The analysis doc lives at `ref/AC_AL_Integration_Analysis_v2.1.md`**, not `.claude/` as the brief says.
4. **Repo dir is `AgentLighthouse`** (capitalized) at the workspace root, via directory junction to `C:\AILab\projects\AgentLighthouse`; likewise `access_control` → `C:\AILab\projects\access_control`.
5. Minor: brief understates app.py's endpoint list (session/summary/receipts/{seq}/verify/{seq} also exist); the separate gateway app (gateway/web.py) additionally serves /fetch, /mcp, /v1/chat/completions, /v1/messages.

## Packaging finding (Phase R item 5)

AgentLighthouse is a **uv workspace** (root `agentlighthouse`, `package = false`, members `core`, `verify`, `governance`). `core/` builds distribution **al-core** (hatchling, `packages = ["al_core"]`, CLI `al`); `verify/` builds **al-verify** (CLI `al-verify`, sole dep `cryptography>=43`). al-core depends on al-verify via `{ workspace = true }`, which does **not** resolve outside that workspace. access_control is a single uv project (not a workspace).

Therefore the `[lighthouse]` extra in access_control's pyproject.toml must declare **two** path sources:

```toml
[project.optional-dependencies]
lighthouse = ["al-core"]

[tool.uv.sources]
al-core   = { path = "../AgentLighthouse/core" }
al-verify = { path = "../AgentLighthouse/verify" }
```

(`al-verify` must be pinned as a source even though only `al-core` is named in the extra, because al-core's own workspace source for it is invisible to an external consumer.) Relative paths resolve through the workspace junctions. Caveat noted for later phases: al_core's `app.py` locates the dashboard via a repo-layout-relative path (`parents[2]/frontend/dist`) that does not survive an installed-wheel layout — irrelevant for a path/editable dependency, relevant if we ever wheel-install.

## What this changes in the plan

- Phase 0 shrinks (item 1 done). Remaining: CI both repos, F-07, F-08.
- Everything Phase AL-0 assumes was re-verified true today; AL-0 scope stands as written.
- The Gatekeeper seam design is compatible with the code as it stands (Engine takes one param today; adding an optional keyword param respects the dependency direction; daemon.py:221 and cli.py:1156 are the two construction sites to touch).

## Open questions (asked one at a time)

1. Brief rule 12 asks to "upgrade current observability interface with industry-level UI … after detailed comparison with MSFT PAN and PAM implementation." The current AL dashboard is Vite/React (trace + performance boards, no approvals UI). This reads as new scope beyond the phased plan — where does it fit (part of AL-0.1's dashboard panel, or a separate later phase)?
2. (held until Q1 is answered)
