# Bug fixes and changes

Bugs that have been fixed, and bugs and changes still open.

Open items come from the documentation audit of **2026-08-17**
([docs/gap-analysis.md](docs/gap-analysis.md) §3), which read the source against
every claim in the documentation. **That audit changed no code** — everything in
§2 below is reported, not fixed.

Ids are stable: `F-nn` findings, `B-nn` fixed bugs, `C-nn` changes.

---

## 1. Fixed

### Bugs found in testing and live use

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
| B-16 | Concurrent sessions could share a `session_id`, and two starting in the same second could share a `trace_id` — which names the log file, so **two sessions' audit trails interleaved in one `.jsonl`** | `context._next_sequence` guarded a file read-modify-write with a `threading.Lock`, which serialises threads within one process but not ten separate `ac connect` processes. A torn read also reset the counter to 0. The same race applied to the generated `AGT-<date>-<seq>`, so two independent agents could take one identity | Ids now carry a random 6-hex suffix (`SES-3f9a1c`, `trace_id` `20260812T091520Z-3f9a1c`) and need no coordination. `_next_sequence` and the `state/*.seq` files were removed rather than locked. `audit.default_agent_id()` gained the same suffix — ten agents on one host were otherwise all `claude-code@HOST` | `test_routegraph.py::TestAgentIdentity::test_same_second_runs_get_distinct_trace_ids` (50 creations inside one second) |
| B-17 | Every `uv run ac …` and `uv sync` failed with `Package metadata name 'agentlighthouse-governance' does not match given name 'al-governance'`, although the standalone tool uses no AgentLighthouse code | AgentLighthouse 0.4.0 renamed its packages (`al-core`, `al-verify`, `al-governance` became `agentlighthouse-core`, `-verify`, `-governance`). `pyproject.toml` took them from a sibling checkout (`../AgentLighthouse`), and uv validates every declared source on each run, including the ones it is not installing. `al-governance` also sat in the default `dev` group | The three packages use their new names and come from one pinned release tag (`[tool.uv.sources]`, git + `tag`). `agentlighthouse-governance` moved to the opt-in `lighthouse-test` group. Standalone and integrated modes have separate commands ([docs/integration/README.md](docs/integration/README.md#2-commands)), and CI runs both | `test_packaging_independence.py` |
| B-18 | `ac rdp` / `ac shell` against a node whose address is a pre-established forward (`preestablished: true`, or any `localhost` endpoint) built a second tunnel to `localhost` from the bastion, which is the bastion itself | Both commands tunnelled to whatever address they were given, without asking whether it was already a forward on this machine | The client is pointed straight at the forward: no tunnel, no hop authentication. `ac rdp` still records `RDP_LAUNCH` (a trail of its own when no session is live), and is refused when only another protocol was forwarded | `test_cli_interactive_leg.py` |

### Changes shipped

| # | Change | Why |
|---|---|---|
| C-01 | Per-node `via:` became the canonical connectivity declaration | A separate `routes:` list described each machine twice, and the two drifted — edges restated a `username`/`domain` the connect path never read. Commenting a machine out also left dangling edges. Neither is expressible once the leg lives inside the node's own block. `routes:` and `path:` still compile to the same graph; combining them with `via:` is refused |
| C-02 | The `ac connect` window became a prompt (`operator_shell.py`) | The window was authenticated and idle, so an operator who wanted to *look* at the machine opened a second connection and retyped every password |
| C-03 | Hop fallback: hold the session at the last authenticated hop when the target leg fails | Throwing away three typed passwords because the last leg refused is the wrong answer. Operations and `ac exec` are withdrawn while degraded, and `:retry` costs no password |
| C-04 | Campaigns (`ac campaign`) | One reviewed brief across many hosts' live sessions. Instructions stay central; the target never supplies work |
| C-05 | `ac reload` | Editing an operation otherwise meant reconnecting, which costs a password per hop — enough friction that people stop iterating |
| C-06 | Direct WinRM (`via: {from: local}`) | A VPN-reachable host has no bastion to anchor a tunnel at. Still declared, never discovered, and recorded as `winrm.direct` because it bypasses every hop |
| C-07 | `package_share` on a host is rejected at load time | A path is a fact about the job, not the machine. As a host field it silently rendered empty and failed on the server; as an operation parameter it is refused up front, by name |
| C-08 | Per-run identity (`AGT-<date>-<suffix>` / `SES-<suffix>` / sortable `trace_id`) | A single static agent id makes concurrent runs indistinguishable, which is exactly when telling them apart matters. Superseded in part by C-12: the suffix was originally a persisted counter |
| C-09 | Canonical action records and `ac timeline` | The trail can be filtered by `action` and correlated by `source`/`target` without parsing prose, and drops into a SIEM without a transform |
| C-10 | Configurable logging location and retention, defaulting outside the repository | The repository sits in a OneDrive-synced folder; captured server output must not be uploaded |
| C-11 | Documentation restructured into `docs/{guides,implementation,reports}` with six core documents | The audit of 2026-08-17. See [docs/gap-analysis.md](docs/gap-analysis.md) |
| C-12 | Identity suffixes became random; `_next_sequence` and `state/*.seq` removed; `ac connect --agent-id` added | See B-16 — C-08's persisted counter could not keep its promise across processes. Explicit naming was env-var-only, which is the wrong default when ten agents each need their own identity |

---

## 2. Open

Nothing below has been fixed. Severity assumes production use with an agent
driving a live session.

### 2.1 Security-relevant

| # | Item | Detail | Severity | Suggested fix |
|---|---|---|---|---|
| F-01 | ~~**`--confirm` does not prove a human approved**~~ **Resolved 2026-11-16** | An agent's gated operation or `CONFIRM`-class command is held in the session (`LocalGatekeeper`, no external plane) until the operator types `:approve <id>` in the `ac connect` window. Bound to the exact commands, one approval per run, lapses into a denial. Also closed: an agent's `--confirm` no longer waves a confirm-class step through an operation that is not marked gated | Residual, Low: a session opened *without* `--agent-id` relies on the client declaring itself from its environment | Open agent sessions with `--agent-id`. Tests in `test_local_approvals.py` |
| F-02 | ~~**`ac exec` is not scoped by `--ops`**~~ **Resolved 2026-11-16** | A `--ops` session refuses `ac exec` / `run_command` (also through `ac mcp`) unless `ac connect --allow-exec`; refusals are audited as `COMMAND_BLOCKED`. `ac logs` stays available, and its path can no longer inject a command (it was pasted unquoted into `tail` on POSIX and into a double-quoted string on Windows) | — | Regression tests in `test_exec_scope.py`, including the injection cases; also verified in real bash and PowerShell |
| F-03 | ~~**RDP launches are not audited**~~ **Resolved 2026-11-16** | `ac rdp` records `RDP_LAUNCH` with node, endpoint, username and whether a credential was staged; a live session records it through the new `rdp_launched` daemon method | — | Regression tests in `test_cli_interactive_leg.py`, `test_daemon.py` |
| F-04 | ~~**No absolute session lifetime**~~ **Resolved 2026-09-01** | `ac connect --max-lifetime <secs>` caps a session from connect, never refreshed by activity (0 = no ceiling, the default); the watchdog closes it and emits `session.lifetime_timeout`. Regression tests in `test_session_lifetime.py` | — | — |
| F-05 | ~~**`logging.level` is validated then ignored**~~ **Resolved 2026-11-16** | It now sets the verbosity of `transport.log` when a session is built. The audit trail is deliberately never filtered by level | — | Tests in `test_logging_setup.py` |
| F-06 | ~~**`transport.log` and `errors.log` grow unbounded**~~ **Resolved 2026-11-16** | Both roll over at 5 MiB (3 backups and 1 backup). A rollover blocked by another process on Windows is retried rather than printed | — | Tests in `test_logging_setup.py` |

### 2.2 Correctness

| # | Item | Detail | Severity | Suggested fix |
|---|---|---|---|---|
| F-07 | ~~**`ac tunnel --port` is silently ignored**~~ **Resolved 2026-08-31** | Both paths now pass `local_port` through; the misleading "unavailable" note is gone — a busy port raises `ConnectionFailed` instead of silently substituting another | — | Regression tests in `test_cli_tunnel.py` |
| F-08 | ~~**`postcheck:` in a brief is never executed**~~ **Resolved 2026-08-31** | `postcheck:` now runs through the same daemon handler as `preflight` after every operation succeeds; a failing postcheck fails the brief (exit 2); skipped when the brief already failed | — | Regression tests in `test_cli_brief_postcheck.py` |
| F-09 | ~~**"Not reached" in an operation report is dead code**~~ **Resolved 2026-11-16** | The report now compares against the steps the run planned (after `--only` / `--start-at`), so a resumed run does not list steps before its start | — | Regression tests in `test_engine.py` |
| F-10 | ~~**`ac shell` / `ac rdp` use the node's own `host`/`port`, not the resolved route leg**~~ **Resolved 2026-11-16** | Both now tunnel to the leg's declared endpoint for their protocol (`interactive:` for RDP), falling back to the leg's address on the node's own port | — | Regression tests in `test_cli_interactive_leg.py` |
| F-11 | ~~**`rules.max_duration_minutes` and `brief.window` are not enforced**~~ **Resolved 2026-11-16** | `ac brief run` starts no further operation once `max_duration_minutes` has passed, and fails the brief. `window` is free text that cannot be parsed reliably, so it stays unenforced and the template and docs now say so | — | Tests in `test_cli_brief_duration.py` |
| F-12 | ~~**`PREFLIGHT` and `COMMAND` are emitted but absent from `audit.ACTIONS`**~~ **Resolved 2026-11-16** | Both added; `test_audit_actions.py` scans the source and fails on any emitted name missing from the list | — | — |
| F-13 | ~~**`check_no_active_install` filters on `$_.SessionId -ne $null`**, which is always true~~ **Resolved 2026-11-16** | The no-op filter is gone; behaviour is unchanged (the `> 2` threshold still allows for the resident msiexec) | — | The check had no tests; four added in `test_brief.py` |

### 2.3 Dead code

| # | Item |
|---|---|
| F-14 | `CredentialStore.discard_after_auth` — never set `True`, including in tests |
| F-15 | `RouteGraph.direct_allowed` — accepted by `build()`, never populated by `config.py` |
| F-16 | `EV_HOP_CONNECTED`, `EV_TRANSFER`, `EV_RDP` — declared constants nothing emits |
| F-17 | `safety.classify/check(extra_rules=…)` — an extension point with no caller |
| F-18 | `Route.is_direct`, `Route.nested_chain`, `Route.psrp_entry`, `Inventory.node_context` — unused helpers |
| F-19 | ~~`context._next_sequence(width=…)` — accepted and immediately `del`eted~~ **Resolved 2026-08-31**: the function was removed outright; ids now use a random suffix, eliminating the cross-process counter race as well |

Each is harmless. Either wire it up or remove it; leaving it suggests a feature
that is not there.

### 2.4 Engineering hygiene

| # | Item | Detail |
|---|---|---|
| F-20 | **No CI pipeline** | No `.github/workflows`, no pre-commit config. The 340 tests run when someone remembers |
| F-21 | **No linter or type checker configured** | No ruff/flake8/mypy settings, despite fully annotated code |
| F-22 | **No coverage gate** | `pytest-cov` is installed; nothing enforces a threshold |
| F-23 | **No git history** | `git log` reports no commits on `master`. Every review, rollback and audit process the documentation recommends assumes version control |
| F-24 | **Stray files in the working tree** | `New Text Document.txt` (11 KB of notes), `disconnect` (one line: a host id), `config/inventory copy.yaml`, `config/inventory_Orig_Copy.yaml`. None is referenced by the code, and the two inventory copies are confusing beside the real one |
| F-25 | **No WinRM test double** | The offline suite cannot exercise `transport/winrm.py`, the nested leg, provider selection or wedge recovery |

### 2.5 Unverified paths

| # | Item | Detail |
|---|---|---|
| F-26 | **The nested Windows→Windows leg has never run against real hardware** | Implemented and unit-tested. It is the flagship topology in every diagram. Verify with `ac probe --deep`, then a read-only operation, before relying on it |
| F-27 | **WinRM through an SSH bastion is only partially proven** | Direct WinRM is verified against Windows Server 2022; the tunnelled variant is implemented and unit-tested |

---

## 3. Requesting a change

Add a row to §2 with a new `F-nn` or `C-nn` id, a one-line detail, a severity,
and a suggested fix. When it ships, move it to §1 with the regression test that
protects it — every fixed bug in §1 has one, and that is the standard.

Cross-references:
[docs/gap-analysis.md](docs/gap-analysis.md) (how each was found),
[docs/production-readiness.md](docs/production-readiness.md) (which of these
block production, and in what order to close them).
