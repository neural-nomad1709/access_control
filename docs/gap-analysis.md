# Gap analysis

What the documentation was missing before the audit of 2026-08-17, what was
found in the code that no document described, what documents described that the
code does not do, and what remains open.

Source of truth throughout: the code in `src/access_control`, the configuration
in `config/`, and a passing run of `uv run pytest` (**340 tests**).

---

## 1. Summary

| Category | Before | After |
|---|---|---|
| Core documents (README, ARCHITECTURE, INSTALLATION, CONFIGURATION, OPERATIONS, SECURITY) | 1 of 6 (README) plus a partial `design.md` | 6 of 6 |
| CLI commands documented with their flags | ~11 of 24, none exhaustively | 24 of 24 |
| Environment variables documented | 2 of 14 | 14 of 14 |
| Audit events documented | The 16 action names only | All 16 actions + 19 `emit`-only events, with fields |
| Session-protocol methods documented | 0 of 15 | 15 of 15 |
| Major features with no documentation | 4 (operator shell, hop fallback, campaigns, NTLM provider selection) | 0 |
| Documented features that do not exist | 3 | 0 (removed or corrected) |
| Stale figures (test counts, verification status) | 5 | 0 |
| Documentation structure | Flat `docs/` + two reports at the repo root | `docs/{guides,implementation,reports}` with an index |

---

## 2. Documentation gaps that were closed

### 2.1 Missing core documents

| Document | Gap | Now |
|---|---|---|
| `ARCHITECTURE.md` | `design.md` covered rationale well but had no component map, no request lifecycle, no authentication/authorization flow, no trust zones, no integration points, no concurrency or error-handling model | Written; `design.md` folded into it |
| `INSTALLATION.md` | Install was four lines in the README. No prerequisites table, no platform matrix, no build step, no validation sequence, no failure modes | Written |
| `CONFIGURATION.md` | No single reference. Fields were scattered across `operations-guide.md`, the YAML comments and the source | Written; every field, default, and security implication |
| `OPERATIONS.md` | Nothing on monitoring, backup, recovery, maintenance or upgrades | Written |
| `SECURITY.md` | The threat model was two paragraphs in `design.md`, covering only the session socket | Written; assets, actors, 17 threats, controls, assumptions, hardening, incident response |
| `CLAUDE_PRODUCTION_GUARDRAILS.md` | Did not exist | Written; every recommendation marked BUILT / CONFIG / GAP |
| `docs/README.md` | No index | Written |

### 2.2 Undocumented functionality found in the code

Each of these existed and worked, and no document mentioned it.

| Feature | Where it lives | Now documented in |
|---|---|---|
| **The operator prompt** — a full REPL in the `ac connect` window, with `:help`, `:status`, `:where`, `:route`, `:retry`, `:timeout`, `:exit`, and `cd` persistence on POSIX hosts | `operator_shell.py` (302 lines) | features.md §9b, runbook step 4, cli-reference |
| **Hop fallback / degraded sessions** — holding the session at the last authenticated hop when the target leg fails, with operations withdrawn and `:retry` available | `session.py` `_degrade_to_hop`, `retry_target` | ARCHITECTURE §9, features.md §9b, runbook |
| **Campaigns** — fan-out of one brief across many live sessions | `campaign.py` (408 lines), `ac campaign` | features.md §5c, instructions-guide, cli-reference |
| **Direct WinRM** (`via: {from: local}` with no bastion) | `session.py` `_connect_winrm` | ARCHITECTURE §5, CONFIGURATION, SECURITY |
| **NTLM provider selection** (`auto`/`sspi`/`python`) and why it exists | `config.AuthConfig`, `transport/winrm.py` | SECURITY §3.5, CONFIGURATION §3.6, features.md §4 |
| **WinRM transport-wedge recovery** | `transport/winrm.py` `_looks_wedged`, `_reopen` | implementation/README, features.md §4 |
| **`ac reload`** | `daemon.do_reload` | features.md §9, runbook, cli-reference |
| **`ac connect --no-shell` / `--no-fallback`** | `cli.connect` | cli-reference, runbook |
| **`ac tunnel --port` / `--remote-port`, `ac rdp --stage-credentials` / `--full-screen`, `ac exec --shell` / `--timeout`, `ac audit --limit`** | `cli.py` | cli-reference |
| **12 environment variables** (`AC_DATA_DIR`, `AC_CONFIG_DIR`, `AC_HOME`, `AC_AGENT_ID`, `AC_PROMPTER`, `AC_NO_GUI_PROMPT`, `AC_KNOWN_HOSTS`, `AC_WINRM_PYTHON_NTLM`, `AC_ALLOW_ENV_CREDENTIALS` and its three per-node forms) | `paths.py`, `context.py`, `credentials.py`, `transport/*` | CONFIGURATION §2 |
| **19 `emit`-only audit events** (`session.degraded`, `session.recovered`, `session.idle_timeout`, `config.reload`, `winrm.direct`, `winrm.ntlm_provider`, `tunnel.preestablished`, `host_key.new`, `host_key.unreadable`, `hop.auth`, `hop.failed`, `probe`, `step.start`, `operation.start`, `operation.end`, `command.blocked`, `permission`, `error`, `preflight`) | `audit.py` and call sites | implementation/audit-events.md |
| **The session wire protocol** — 15 methods, framing, size limits, token handling, deferred close | `daemon.py` | implementation/session-protocol.md |
| **`transport.log` and `errors.log`** | `logging_setup.py` | CONFIGURATION §1, OPERATIONS §5 |
| **Node fields `role`, `vars`, `vars.allow_direct`, `prompt_username`** | `config.py` | CONFIGURATION §3.3, operations-guide |
| **Every timeout and limit** (idle 1800 s, watchdog 15 s, output clamp 20 000, collect clamp 6 000, socket 8 MiB, WinRM 60/90/30 s, campaign parallelism 8, …) | throughout | CONFIGURATION §7 |
| **Preflight check inventory and ordering** | `preflight.py` | CONFIGURATION §5.1, cli-reference |
| **Exit-code conventions** (`0`/`1`/`2`/`130`) | `cli.py` | cli-reference |

### 2.3 Documented features that do not exist in the code

| Claim | Where | Reality | Action |
|---|---|---|---|
| Tool names `read_task_brief` and `verify_connection` | `instructions-guide.md` "What the agent must do" | No such interface. The CLI is the only interface | Rewritten as `ac brief validate` / `ac verify` |
| "There is no fan-out, deliberately" | `instructions-guide.md` | Campaigns are implemented and shipped with an example | Corrected, with the campaign section added |
| "The WinRM path is unproven against a real Windows host" | `features.md` limitation 12 | Direct WinRM was verified against a live Windows Server 2022 host on 2026-08-13. Only the **nested** Windows-to-Windows leg remains unproven | Narrowed to the nested leg |
| `rules:` described as "the enforced boundaries" | `instructions-guide.md` | Only `reboot_allowed` and `stop_on_first_failure` are enforced | Enforcement table added |
| Link to `../.claude/STATUS.md` | `features.md` | `STATUS.md` is at the repo root | Fixed |
| "170 tests, all passing" / "306" / "325" / "336" | `PLAN.md`, `testing.md`, `STATUS.md` | 340 | All corrected |

### 2.4 Structural problems

| Problem | Fix |
|---|---|
| Two customer field reports sitting at the repository root, unexplained, alongside project docs | Moved to `docs/reports/` with a README explaining what they are and are not |
| Flat `docs/` mixing reference, guides and internals | Split into `docs/`, `docs/guides/`, `docs/implementation/`, `docs/reports/` |
| No entry point — a reader had to guess between `design.md`, `features.md` and `runbook.md` | `docs/README.md` routes by task and by audience |
| Duplicate content: the hop chain, the RDP rationale, the tunnel explanation and the credential model each appeared in three or four documents | Kept once in the owning document, referenced elsewhere |
| Terminology drift (`hop` vs `node`, `channel` vs `shape`, `brief` vs `instruction`) | Glossary in `docs/README.md`; usage aligned |

---

## 3. Functional gaps found in the code

These are **not** documentation problems. They are behaviours a reader would
reasonably expect that the code does not provide, or small defects found while
verifying the docs against the source. Nothing here has been changed — this
audit did not modify behaviour.

Tracked for triage in [../BugFixNchange.md](../BugFixNchange.md).

### 3.1 Security-relevant

| # | Gap | Detail | Severity |
|---|---|---|---|
| F-01 | `--confirm` does not prove a human approved | The flag is passed by the caller. An agent driving a live session can self-approve any gated operation | **High** for agent deployments |
| F-02 | `ac exec` / `run_command` is not scoped by `--ops` | The session allow-list covers catalogue operations only. A "restricted" session still permits arbitrary ad-hoc commands, gated only by the deny-list | **High** |
| F-03 | RDP launches are not audited | `RDP_LAUNCH` is a declared action but nothing emits it. `ac rdp` opens a tunnel through the chain (which *is* audited) and launches `mstsc` with no record of the interactive session | Medium |
| F-04 | No absolute session lifetime | **Resolved 2026-09-01**: `ac connect --max-lifetime <secs>` bounds a session from connect regardless of activity; the watchdog closes it (`session.lifetime_timeout`). Tests in `test_session_lifetime.py` | — |
| F-05 | `logging.level` is validated but never applied | The field is parsed, rejected if invalid, reported in `to_dict()` — and then ignored. Nothing filters records by level | Low, but misleading |
| F-06 | `transport.log` and `errors.log` grow unbounded | Retention prunes `*.jsonl` and `*.md` only | Low |

### 3.2 Correctness

| # | Gap | Detail | Severity |
|---|---|---|---|
| F-07 | `ac tunnel --port` is silently ignored | **Resolved 2026-08-31**: both CLI paths pass `local_port` through; a busy port now raises `ConnectionFailed` rather than silently substituting another. Regression tests in `test_cli_tunnel.py` | — |
| F-08 | `postcheck:` in a brief is parsed but never executed | **Resolved 2026-08-31**: runs via the same daemon handler as `preflight` after the operations succeed; failure fails the brief. Regression tests in `test_cli_brief_postcheck.py` | — |
| F-09 | "Not reached" in an operation report is dead code | `report_markdown` computes `reached = {s.step_id for s in self.steps}` and then filters `self.steps` for ids *not* in that set — always empty. Steps skipped after a failure are never listed | Low |
| F-10 | `ac shell` and `ac rdp` use the node's own `host`/`port` rather than the resolved route leg | `ac tunnel` correctly uses `route.leg_for(node)`. For a node with multiple `via:` blocks, or an explicit `hostname:` that differs from its leg, these two can dial a different address than the route says | Low |
| F-11 | `rules.max_duration_minutes` and `brief.window` are not enforced | Recorded and rendered only | Low (documented) |
| F-12 | `PREFLIGHT` and `COMMAND` actions are not in `audit.ACTIONS` | Both are emitted. The list is documentation rather than an enum, so nothing breaks, but a consumer building a filter from `ACTIONS` would miss them | Low |
| F-13 | `check_no_active_install` filters on `$_.SessionId -ne $null`, which is always true | The `> 2` threshold compensates, but the filter does nothing | Low |

### 3.3 Dead or unreachable code

| # | Item | Detail |
|---|---|---|
| F-14 | `CredentialStore.discard_after_auth` | Never set to `True` anywhere, including tests |
| F-15 | `RouteGraph.direct_allowed` | Accepted by `build()` but never populated by `config.py` |
| F-16 | `EV_HOP_CONNECTED`, `EV_TRANSFER`, `EV_RDP` | Declared event constants that nothing emits |
| F-17 | `safety.classify/check(extra_rules=…)` | An extension point with no caller |
| F-18 | `Route.is_direct`, `Route.nested_chain`, `Route.psrp_entry`, `Inventory.node_context` | Unused helpers |
| F-19 | `context._next_sequence(width=…)` | **Resolved 2026-08-31**: the function was removed; session/agent ids now use a random suffix instead of a persisted counter, which also removes the cross-process race on `state/*.seq` |

### 3.4 Engineering hygiene

| # | Gap | Detail |
|---|---|---|
| F-20 | **No CI pipeline** | No `.github/workflows`, no pre-commit configuration. The 340 tests run only when someone remembers |
| F-21 | **No linter or type checker configured** | No ruff/flake8/mypy settings, despite the code being fully annotated and written to a consistent style |
| F-22 | **No coverage gate** | `pytest-cov` is a dependency; nothing enforces a threshold |
| F-23 | **No git history** | The working tree has no commits (`git log` reports none on `master`). Every review and rollback mechanism this documentation recommends assumes version control |
| F-24 | **Stray files in the working tree** | `New Text Document.txt` (11 KB of notes), `disconnect` (a one-line file containing a host id), `config/inventory copy.yaml`, `config/inventory_Orig_Copy.yaml`. None is referenced by the code; the two inventory copies are confusing next to the real one |
| F-25 | **No WinRM test double** | The offline suite cannot exercise `transport/winrm.py`, the nested leg, provider selection or wedge recovery |

---

## 4. Documentation debt still open

Things a future pass should add, none of which block use today.

| # | Item | Why it matters |
|---|---|---|
| D-01 | A worked **nested-winrm** example, end to end, once that path is verified against real hardware | It is the flagship topology in every diagram and the least proven in practice |
| D-02 | Screenshots or captured terminal sessions for the first-run flow | The prose is complete, but a first-time user benefits from seeing the prompt and the panels |
| D-03 | A migration note if the older `routes:` / `path:` declaration styles are ever retired | They are documented as accepted; a deprecation needs a path |
| D-04 | Per-operation documentation for the shipped catalogue | `install-package`, `patch-windows`, `windows-health`, `collect-diagnostics`, `linux-health`, `linux-service-status` and `run-command` are documented by their YAML comments only |
| D-05 | A CONTRIBUTING guide | Implied by `implementation/README.md` conventions, but not stated |
| D-06 | Recorded evidence for the live-verification claims | `testing.md` cites real runs; the underlying trails are not kept in the repo |

---

## 5. Method

1. Read every source file in `src/access_control` (≈11 000 lines) and every YAML
   in `config/`.
2. Ran the test suite to establish the real figure (340 passing) rather than
   quoting any document.
3. Enumerated the CLI surface from `cli.py`, the environment surface from every
   `os.environ` reference, the audit surface from every `emit`/`action` call
   site, and the protocol surface from every `do_*` method.
4. Checked each claim in each existing `.md` against the code, recording those
   that were stale, wrong, or referred to things that do not exist.
5. Restructured the tree, rewrote what was inaccurate, and wrote what was
   missing.

No source file was modified. Every finding in §3 is reported, not fixed.
