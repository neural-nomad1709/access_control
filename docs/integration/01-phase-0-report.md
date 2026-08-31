# Phase 0 — Hygiene: Report

Date: 2026-08-31 · Branch: `wip/phase-0-hygiene` (access_control)

## What changed

1. **F-07 fixed** (`ac tunnel --port` silently ignored). Both CLI paths now pass
   `local_port` through to the session layer, which already accepted it end to end.
   The misleading "the requested port was unavailable" note is removed: `LocalTunnel`
   raises `ConnectionFailed` on a failed bind rather than falling back, so a busy
   port is now a clear error, never a silent substitute. Tests first:
   `tests/test_cli_tunnel.py` (3 tests, all failing before the fix).
2. **F-08 fixed** (`postcheck:` parsed but never executed). `ac brief run` now sends
   the postcheck spec through the same daemon `preflight` handler after every
   operation succeeds; a failing postcheck fails the brief (exit 2); it is skipped
   when the brief already failed (its expectations were never established). The JSON
   payload carries the postcheck report. Tests first: `tests/test_cli_brief_postcheck.py`
   (4 tests, 2 failing before the fix, 2 guarding unchanged behaviour).
3. **CI added** to access_control: `.github/workflows/ci.yml` — `uv sync --frozen` +
   `uv run pytest` on Ubuntu and Windows. No lint/type step: the repo has no such
   tooling configured, and the brief forbids adding new linters without asking.
4. **Docs refreshed**: F-07/F-08 marked resolved in `BugFixNchange.md`,
   `docs/gap-analysis.md`, `STATUS.md`, `docs/production-readiness.md` (R-12 also
   marked resolved by the CI workflow); STATUS.md test count 341 → 348.

## Test evidence

| Point | Count |
|---|---|
| Before Phase 0 | 341 passed |
| After Phase 0 | **348 passed** (7 new: 3 F-07, 4 F-08) |
| AgentLighthouse (untouched) | 632 passed, 12 skipped |

## What was NOT done, and why

- **Phase 0.1 (`credentials.py` / `.gitignore`)** — already done upstream in commit
  `dd1fc82` before this work started; verified tracked, pattern narrowed.
- **CI for AgentLighthouse** — already exists upstream (`.github/workflows/ci.yml`:
  pytest + release-gate demos + image build). Nothing to add.
- **ruff/mypy in CI** — the repo has neither configured; adding new linters requires
  Amit's sign-off per the brief (open items F-20/F-21/F-22).

## Open risks

- The CI workflow is untested until pushed to GitHub (no local Actions runner).
  YAML validated; `uv sync --frozen` verified against the current lockfile.
- Untracked `STATUS.local.md` remains in the working tree (ignored via `*.local.md`),
  by prior arrangement.
