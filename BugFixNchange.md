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
| F-01 | **`--confirm` does not prove a human approved** | The flag is passed by the caller, so an agent on a live session can self-approve any gated operation | **High** | An interactive approval gate the session itself satisfies (a prompt in the `ac connect` window), not a flag on the client |
| F-02 | **`ac exec` is not scoped by `--ops`** | The session allow-list covers catalogue operations only. A "restricted" session still permits arbitrary ad-hoc commands, gated only by the deny-list | **High** | Extend the allow-list to `run_command`, or add a session mode that disables ad-hoc execution |
| F-03 | **RDP launches are not audited** | `RDP_LAUNCH` is a declared action that nothing emits. The tunnel is recorded; the interactive session is not | Medium | Emit `RDP_LAUNCH` from `cli._run_rdp` with node, endpoint, username and whether a credential was staged |
| F-04 | **No absolute session lifetime** | Only an idle timeout, which activity refreshes indefinitely | Medium | A `--max-lifetime` alongside `--idle-timeout` |
| F-05 | **`logging.level` is validated then ignored** | Parsed, rejected if invalid, reported in `to_dict()`, and applied to nothing | Low (misleading) | Apply it, or remove the field |
| F-06 | **`transport.log` and `errors.log` grow unbounded** | Retention prunes `*.jsonl` and `*.md` only | Low | Size-based rotation, or include them in pruning |

### 2.2 Correctness

| # | Item | Detail | Severity | Suggested fix |
|---|---|---|---|---|
| F-07 | ~~**`ac tunnel --port` is silently ignored**~~ **Resolved 2026-08-31** | Both paths now pass `local_port` through; the misleading "unavailable" note is gone — a busy port raises `ConnectionFailed` instead of silently substituting another | — | Regression tests in `test_cli_tunnel.py` |
| F-08 | ~~**`postcheck:` in a brief is never executed**~~ **Resolved 2026-08-31** | `postcheck:` now runs through the same daemon handler as `preflight` after every operation succeeds; a failing postcheck fails the brief (exit 2); skipped when the brief already failed | — | Regression tests in `test_cli_brief_postcheck.py` |
| F-09 | **"Not reached" in an operation report is dead code** | `report_markdown` filters `self.steps` against a set built from `self.steps` — always empty, so steps skipped after a failure are never listed | Low | Compare against the operation's full step list |
| F-10 | **`ac shell` / `ac rdp` use the node's own `host`/`port`, not the resolved route leg** | `ac tunnel` correctly uses `route.leg_for(node)`. For a node with multiple `via:` blocks, or an explicit `hostname:` differing from its leg, these can dial a different address than the route declares | Low | Resolve the leg in all three commands |
| F-11 | **`rules.max_duration_minutes` and `brief.window` are not enforced** | Recorded and rendered only | Low (documented) | Enforce a wall-clock ceiling in `ac brief run`, or document them as advisory in the template too |
| F-12 | **`PREFLIGHT` and `COMMAND` are emitted but absent from `audit.ACTIONS`** | Nothing breaks — the list is documentation — but a consumer building a filter from it would miss both | Low | Add both names |
| F-13 | **`check_no_active_install` filters on `$_.SessionId -ne $null`**, which is always true | The `> 2` threshold compensates, so the check still works | Low | Drop the filter, or make it meaningful |

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
block production, and in what order to close them),
[STATUS.md](STATUS.md) (current state).
