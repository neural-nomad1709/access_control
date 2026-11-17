# Bug fixes and changes

The single tracker for access_control: what each release fixed and changed, and
what is still open. Ids are stable: `B-nn` bugs found in use, `F-nn` findings
from the code audit of 2026-08-17, `C-nn` changes, `D-nn` documentation debt.

---

## 1. Releases

### v0.2.1 (2026-11-16)

The standalone product no longer depends on AgentLighthouse, and every
security and correctness finding from the 2026-08-17 audit is closed.

| Area | What changed | Ids |
|---|---|---|
| Install | Standalone by default: no AgentLighthouse package, no sibling checkout. The integrated mode installs a pinned AgentLighthouse release with its own commands | B-17 |
| Agent approvals | An agent's `--confirm` no longer approves its own gated work. The request is held until the operator types `:approve <id>` in the `ac connect` window | F-01 |
| Session scope | `ac connect --ops` also refuses `ac exec` unless `--allow-exec` is given. `ac logs` paths can no longer carry a command | F-02 |
| Audit | `ac rdp` records `RDP_LAUNCH`; `PREFLIGHT` and `COMMAND` are listed in `audit.ACTIONS` | F-03, F-12 |
| Logging | `logging.level` sets `transport.log` verbosity; `transport.log` and `errors.log` roll over at 5 MiB | F-05, F-06 |
| Interactive | `ac shell` / `ac rdp` dial the address the route declares, and use a pre-established forward as it is | F-10, B-18 |
| Briefs | `rules.max_duration_minutes` is enforced | F-11 |
| Reports | Failed operations list the steps they never reached | F-09 |
| Docs | Split into the standalone product and the AgentLighthouse integration; trackers merged into this file | C-13 |

Tests: 516 standalone (3 skipped), 554 integrated. CI runs both modes on
Ubuntu and Windows.

### v0.2.0 (2026-09-01)

The AgentLighthouse integration (Gatekeeper seam, signed ledger, `ac mcp`),
`--max-lifetime` (F-04), `ac tunnel --port` (F-07), brief `postcheck:` (F-08),
the cp1252 console fix and CI. History:
[docs/integration/history.md](docs/integration/history.md).

The last commit before the integration work is tagged
`pre-agentlighthouse-integration`.

---

## 2. Fixed

### 2.1 Bugs found in testing and live use

| # | Bug | Cause | Fix | Regression test |
|---|---|---|---|---|
| B-01 | `key+password` authentication raised `AttributeError` instead of proceeding to the password stage — the exact path the production bastion uses | `PartialAuthentication` is not re-exported at Paramiko's top level in 5.x | Import it from `paramiko.ssh_exception` | `test_e2e.py::TestLoopOneHappyPath` asserts the auth sequence |
| B-02 | `rm` was ungated on Unix while `Remove-Item` was gated on Windows | The deny-list was reviewed against Windows examples only | POSIX rules added for `rm`, `mv`, `truncate`, `chown`, `chgrp`, `chmod`, `kill` | `test_security.py::test_posix_file_and_process_changes_need_confirmation` |
| B-03 | `ac disconnect` raced its own reply and returned a connection error instead of the status it is owed | The handler tore the listener down before the reply was on the wire | Teardown deferred until after the reply, in the handler's `finally` | `test_daemon.py::test_close_returns_the_report_before_tearing_down` |
| B-04 | `linux-health` returned an empty disk section on AIX | AIX's `df` has no `-h`, and `2>/dev/null` hid the failure | Probe for the flag instead of hiding the error | Covered by the operation's own shape |
| B-05 | The disk-space preflight reported 0.00 GB free on an AIX host with terabytes | Column layouts differ — AIX puts Free in column 3 and `%Used` in 4 | Use `df -Pk` (POSIX output), where column 4 is always Available | `test_brief.py` |
| B-06 | `\breboot\b` matched the word inside a comment describing exit code 3010, gating a step that reboots nothing | An unanchored word-boundary pattern | Anchored to command position; whole-line `#` comments stripped before classification | `test_security.py::test_a_comment_mentioning_reboot_is_not_an_instruction` |
| B-07 | `\b/x\b` never matched ` /x `, so `msiexec /x` (an uninstall) was ungated | A word boundary fails before `/` after a space | `[/-]x\b` | `test_security.py` (the `msiexec /x` case) |
| B-08 | Expectations were not templated, so `stdout_contains: '{{package}}'` could never match | Rendering was applied to `run:` only | `resolve_expect` renders the three string expectation forms | `test_engine.py::test_expectations_are_templated` |
| B-09 | A dry run enforced policy and reported a gated step as "blocked" instead of showing what would happen | Policy was checked rather than reported in the dry-run branch | Dry run reports the verdict; nothing is enforced because nothing is sent | `test_engine.py::test_dry_run_reports_gating_instead_of_blocking` |
| B-10 | The permission refusal rendered the preview *without* the operator's parameters, so it raised "missing parameter" instead of showing the commands to approve | `preview()` was called with no params | The refusal renders with the actual parameters | `test_engine.py::test_gated_operation_refuses_without_confirmation`; `test_e2e.py` step 3 |
| B-11 | Rich markup ate `[math]::Round` in previews, so the operator approved text that differed from what would run | Remote text was printed through the markup parser | `cli._raw` / `_raw_panel` with `markup=False` for anything remote | Exercised by `ac preview` |
| B-12 | A single malformed line in `known_hosts` raised `InvalidHostKey` and made every connection impossible | The whole file failed to load | A corrupt file is treated as empty (conservative — falls through to the unknown-key path) and recorded as `host_key.unreadable` | `test_e2e.py::test_changed_host_key_is_fatal` exercises the load path |
| B-13 | WinRM failed with `SEC_E_LOGON_DENIED` on a direct route, looking exactly like a wrong password | Client Group Policy *Restrict NTLM: Outgoing = Deny* makes Windows SSPI refuse **locally**, before any packet is sent | `auth.ntlm_provider: auto` resolves per route: SSPI through a tunnel, pure-Python for a direct leg. Recorded in a `winrm.ntlm_provider` audit event | Unit-checked (provider resolution) |
| B-14 | After a while every WinRM request returned an empty `Bad HTTP response … Code: 400` | The pure-Python NTLM provider desynced its message-seal counters, which live in the pypsrp client's auth context | `_looks_wedged` detection, `_reopen` rebuilds the whole client reusing the stored credential, one transparent retry of the same script | Unit-checked (wedge detection and rebuild) |
| B-15 | Paramiko protocol chatter (`unhandled type 3`) printed into the middle of a password prompt and read like a failure | Nothing had configured a handler, so `logging.lastResort` printed to stderr | Library loggers routed to `<log dir>/transport.log` through a redacting filter, with `propagate = False` | — |
| B-16 | Concurrent sessions could share a `session_id`, and two starting in the same second could share a `trace_id` — which names the log file, so **two sessions' audit trails interleaved in one `.jsonl`** | A file-based sequence counter guarded by a `threading.Lock`, which serialises threads within one process but not separate `ac connect` processes | Ids carry a random 6-hex suffix (`SES-3f9a1c`, `trace_id` `20260812T091520Z-3f9a1c`) and need no coordination; the counter and its `state/*.seq` files were removed | `test_routegraph.py::TestAgentIdentity::test_same_second_runs_get_distinct_trace_ids` |
| B-17 | Every `uv run ac …` and `uv sync` failed with `Package metadata name 'agentlighthouse-governance' does not match given name 'al-governance'`, although the standalone tool uses no AgentLighthouse code | AgentLighthouse 0.4.0 renamed its packages. `pyproject.toml` took them from a sibling checkout, and uv validates every declared source on each run, including ones it is not installing | The packages use their new names and come from one pinned release tag (`[tool.uv.sources]`, git + `tag`); `agentlighthouse-governance` moved to the opt-in `lighthouse-test` group; CI runs both modes | `test_packaging_independence.py` |
| B-18 | `ac rdp` / `ac shell` against a node whose address is a pre-established forward built a second tunnel to `localhost` from the bastion, which is the bastion itself | Both commands tunnelled to whatever address they were given | The client is pointed straight at the forward: no tunnel, no hop authentication. `ac rdp` still records `RDP_LAUNCH`, and is refused when only another protocol was forwarded | `test_cli_interactive_leg.py` |

### 2.2 Audit findings closed

From the code audit of 2026-08-17, which read the source against every claim in
the documentation.

| # | Finding | Fixed | How | Regression test |
|---|---|---|---|---|
| F-01 | `--confirm` did not prove a human approved: an agent could approve its own gated operation | 2026-11-16 | An agent's gated operation or `CONFIRM`-class command is held in the session (`LocalGatekeeper`) until the operator types `:approve <id>` at the `ac connect` prompt. Bound to the exact commands, one approval per run, lapses into a denial. An agent's `--confirm` also no longer waves a confirm-class step through an operation not marked gated | `test_local_approvals.py` |
| F-02 | `ac exec` was not scoped by `--ops` | 2026-11-16 | A `--ops` session refuses `ac exec` / `run_command` unless `--allow-exec`. `ac logs` paths are escaped so they cannot carry a command | `test_exec_scope.py` |
| F-03 | RDP launches were not audited | 2026-11-16 | `RDP_LAUNCH` with node, endpoint, username and whether a credential was staged | `test_cli_interactive_leg.py`, `test_daemon.py` |
| F-04 | No absolute session lifetime | 2026-09-01 | `ac connect --max-lifetime <secs>`, measured from first connect, never refreshed | `test_session_lifetime.py` |
| F-05 | `logging.level` was validated, then ignored | 2026-11-16 | Sets the verbosity of `transport.log`. The audit trail is never filtered by level | `test_logging_setup.py` |
| F-06 | `transport.log` and `errors.log` grew unbounded | 2026-11-16 | Both roll over at 5 MiB (3 backups and 1) | `test_logging_setup.py` |
| F-07 | `ac tunnel --port` was silently ignored | 2026-08-31 | The port reaches the transport; a busy port is an error, never a silent substitute | `test_cli_tunnel.py` |
| F-08 | A brief's `postcheck:` was never executed | 2026-08-31 | Runs after the operations succeed; a failure fails the brief | `test_cli_brief_postcheck.py` |
| F-09 | "Not reached" in an operation report was dead code | 2026-11-16 | Compared against the steps the run planned | `test_engine.py` |
| F-10 | `ac shell` / `ac rdp` used the node's own address, not the route leg | 2026-11-16 | Both use the leg's endpoint for their protocol (`interactive:` for RDP) | `test_cli_interactive_leg.py` |
| F-11 | `rules.max_duration_minutes` and `brief.window` were not enforced | 2026-11-16 | `ac brief run` starts no operation after the ceiling. `window` is free text and documented as such | `test_cli_brief_duration.py` |
| F-12 | `PREFLIGHT` and `COMMAND` were emitted but absent from `audit.ACTIONS` | 2026-11-16 | Added; a test scans the source for emitted names | `test_audit_actions.py` |
| F-13 | `check_no_active_install` had an always-true filter | 2026-11-16 | Removed; behaviour unchanged | `test_brief.py` |
| F-19 | `context._next_sequence(width=…)` accepted and discarded an argument | 2026-08-31 | The function was removed with B-16 | — |
| F-20 | No CI pipeline | 2026-08-31 | `.github/workflows/ci.yml`: both modes, Ubuntu and Windows | — |
| F-23 | No git history | 2026-08-31 | The repository is under git with a remote | — |
| F-24 | Stray files in the working tree | 2026-11-16 | None is tracked. Local copies are covered by `.gitignore` | — |

### 2.3 Changes shipped

| # | Change | Why |
|---|---|---|
| C-01 | Per-node `via:` became the canonical connectivity declaration | A separate `routes:` list described each machine twice, and the two drifted. `routes:` and `path:` still compile to the same graph; combining them with `via:` is refused |
| C-02 | The `ac connect` window became a prompt (`operator_shell.py`) | The window was authenticated and idle, so an operator who wanted to *look* at the machine opened a second connection and retyped every password |
| C-03 | Hop fallback: hold the session at the last authenticated hop when the target leg fails | Throwing away typed passwords because the last leg refused is the wrong answer. Operations and `ac exec` are withdrawn while degraded, and `:retry` costs no password |
| C-04 | Campaigns (`ac campaign`) | One reviewed brief across many hosts' live sessions. Instructions stay central; the target never supplies work |
| C-05 | `ac reload` | Editing an operation otherwise meant reconnecting, which costs a password per hop |
| C-06 | Direct WinRM (`via: {from: local}`) | A VPN-reachable host has no bastion to anchor a tunnel at. Still declared, never discovered, and recorded as `winrm.direct` |
| C-07 | `package_share` on a host is rejected at load time | A path is a fact about the job, not the machine |
| C-08 | Per-run identity (`AGT-<date>-<suffix>` / `SES-<suffix>` / sortable `trace_id`) | A single static agent id makes concurrent runs indistinguishable |
| C-09 | Canonical action records and `ac timeline` | The trail can be filtered by `action` and correlated by `source`/`target`, and drops into a SIEM without a transform |
| C-10 | Configurable logging location and retention, defaulting outside the repository | The repository sits in a OneDrive-synced folder; captured server output must not be uploaded |
| C-11 | Six core documents plus `docs/{guides,implementation}` | The audit of 2026-08-17 found the documentation flat, partial and in places wrong |
| C-12 | `ac connect --agent-id` | Explicit naming was env-var-only, which is the wrong default when several agents each need their own identity |
| C-13 | Documentation split into the standalone product and `docs/integration/`; the three trackers merged into this file | One place to look for what is open; no instructions that mix the two install modes |

---

## 3. Open

### 3.1 Residual risk

| # | Item | Detail | Severity |
|---|---|---|---|
| F-01r | Agent detection without `--agent-id` relies on the client | On a session opened from a plain terminal *without* `--agent-id`, a request is treated as an agent's only when the client command declares itself from its environment. A deliberately evasive agent could strip that | Low. Open every agent session with `--agent-id` |

### 3.2 Dead code

| # | Item |
|---|---|
| F-14 | `CredentialStore.discard_after_auth` — never set `True`, including in tests |
| F-15 | `RouteGraph.direct_allowed` — accepted by `build()`, never populated by `config.py` |
| F-16 | `EV_HOP_CONNECTED`, `EV_TRANSFER` — declared event constants nothing emits |
| F-17 | `safety.classify/check(extra_rules=…)` — an extension point with no caller |
| F-18 | `Route.is_direct`, `Route.nested_chain`, `Route.psrp_entry`, `Inventory.node_context` — unused helpers |

Each is harmless. Either wire it up or remove it; leaving it suggests a feature
that is not there.

### 3.3 Engineering hygiene

| # | Item | Detail |
|---|---|---|
| F-21 | No linter or type checker configured | No ruff/mypy settings, despite fully annotated code |
| F-22 | No coverage gate | `pytest-cov` is installed; nothing enforces a threshold |
| F-25 | No WinRM test double | The offline suite cannot exercise `transport/winrm.py`, the nested leg, provider selection or wedge recovery |
| F-28 | `test_same_second_runs_get_distinct_trace_ids` can fail by chance | 50 ids with a 6-hex random suffix collide about once in 14 000 runs. Widening the suffix changes log file names |

### 3.4 Unverified paths

| # | Item | Detail |
|---|---|---|
| F-26 | The nested Windows→Windows leg has never run against real hardware | Implemented and unit-tested. Verify with `ac probe --deep`, then a read-only operation, before relying on it |
| F-27 | WinRM through an SSH bastion is only partly proven | Direct WinRM is verified against Windows Server 2022; the tunnelled variant is implemented and unit-tested |

### 3.5 Documentation debt

| # | Item | Why it matters |
|---|---|---|
| D-01 | A worked nested-winrm example, end to end, once F-26 is verified | It is the flagship topology and the least proven in practice |
| D-02 | Captured terminal sessions for the first-run flow | A first-time user benefits from seeing the prompt and the panels |
| D-03 | A migration note if the `routes:` / `path:` declaration styles are ever retired | They are documented as accepted; a deprecation needs a path |
| D-04 | Per-operation documentation for the shipped catalogue | The operations are documented by their YAML comments only |
| D-05 | A CONTRIBUTING guide | Implied by `implementation/README.md` conventions, but not stated |

---

## 4. Adding an item

Add a row to §3 with a new id, a one-line detail and a severity. When it ships,
move it to §2 with the regression test that protects it, and list it under the
release in §1. Every fixed bug has a regression test; that is the standard.

Which open items matter for production, and in what order:
[docs/production-readiness.md](docs/production-readiness.md).
