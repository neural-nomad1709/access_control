# STATUS — access_control

_Last updated: **2026-09-01**. Purpose: hand a fresh session the current state
without re-deriving it._

| | |
|---|---|
| Version | `0.1.0` |
| Tests | **462 passing** (`uv run pytest`, fully offline, ~25 s; 27 need the `[lighthouse]` extra and skip on a plain install) |
| Source | ~11 000 lines across 27 modules in `src/access_control` |
| Documentation | Complete as of the 2026-08-17 audit — see [docs/README.md](docs/README.md) |
| Version control | On `main`, pushed to GitHub. `src/access_control/credentials.py` is tracked — the old `*credential*` ignore pattern was narrowed to credential material only (`credentials.json`, `*credentials.y*ml`, `*credentials.txt`); see [2026-08-20 follow-ups](#follow-ups-owed-from-this-session) |

---

## AgentLighthouse integration (2026-08-31, in progress)

access_control is being wired to AgentLighthouse (sibling clone in the
`ac-al_integration/` workspace) as its governance plane: AL supplies the
out-of-band approval gate (R-01), per-identity default-deny tool policy (R-02),
output scanning + taint (R-06/R-07), and a signed tamper-evident receipt ledger
(R-09). AL stays strictly optional — the default `NullGatekeeper` keeps a plain
install byte-identical to today. Plan: `ref/AC_AL_Integration_Analysis_v2.1.md`
in the workspace; per-phase reports in [docs/integration/](docs/integration/).

| Phase | State | Branch | Evidence |
|---|---|---|---|
| R — context load | **Done** | `wip/phase-r-context` | [00-context.md](docs/integration/00-context.md); both suites green |
| 0 — hygiene (F-07, F-08, CI) | **Done, review-clean** | `wip/phase-0-hygiene` | [01-phase-0-report.md](docs/integration/01-phase-0-report.md); tests 341 → 351 |
| AL-0 — AL pre-work (approvals surface, persistence, detect-secrets, embed facade, receipt v1.1) | **Done, review-clean** | `wip/phase-al-0` (AgentLighthouse) | [02-phase-al-0-report.md](docs/integration/02-phase-al-0-report.md); AL tests 632 → 683 |
| 1 — evidence (Gatekeeper seam, receipt sink) | **Done, review-clean** | `wip/phase-1-evidence` | [03-phase-1-report.md](docs/integration/03-phase-1-report.md); tests 351 → 372; fake-SSH e2e ledger verifies, tamper detected; 8 review findings fixed |
| 2 — enforcement (three engine.py call sites) | **Done, review-clean** | `wip/phase-2-enforcement` | [04-phase-2-report.md](docs/integration/04-phase-2-report.md); tests 372 → 419; acceptance a–d proven with the real gatekeeper; 8 review findings fixed |
| 3 — mediated agent path (MCP) | **Done, review-clean** | `wip/phase-3-mcp` | [05-phase-3-report.md](docs/integration/05-phase-3-report.md); tests 419 → 447; agent runs read-only op via proxy, every hop receipted, drift refused; 8 review findings fixed |
| 4 — governance | **Done, review-clean** | `wip/phase-4-governance` (both repos) | [06-phase-4-report.md](docs/integration/06-phase-4-report.md); ac 447 → 462, AL 687 → 699; 5 review findings fixed; F-04, real budget enforcement, attestation test, SIEM doc |

**All phases done and review-clean.** Closing checks (brief rules 10–11) complete:
two full test loops passed identically in both suites (ac 462, AL 699/12 skipped;
no flakiness or order-dependence); docs refreshed (both READMEs, integration docs).
Open loose ends, non-blocking: `.claude/settings.json` dropped 5 pre-integration
OneDrive allow entries in Phase 3 (restore on request); AL's approvals endpoint
still receipts resolutions as `mcp_tool_call` (ac side uses `permission_request`).
Nothing is committed to `main` in either repo — every phase is on its `wip/…`
branch awaiting your merge decision.

### Phase 4 delivered (Amit's calls: budgets enforced, SIEM doc-only, attestation test)

- **F-04 absolute session lifetime** — `ac connect --max-lifetime <secs>`;
  watchdog closes an over-age session (`session.lifetime_timeout`), status shows
  the remaining ceiling.
- **Per-actor budgets, actually enforced** — AL's `max_tool_calls_per_min` was
  declared-not-enforced; now a sliding-60s-window `BudgetTracker` at the
  ActionGate denies the N+1th call with a receipted `BUDGET_EXCEEDED`. Shipped
  policies set a generous `120/min` tripwire.
- **Posture attestation covering ac operations** — a test builds the governance
  attestation from an ac-driven ledger and proves ac's actions are counted and
  the artefact verifies with `al-verify` (al-governance is a dev-only dep).
- **SIEM combined stream** — `docs/integration/siem-combined-stream.md`: ac's
  JSONL + AL's ECS/MITRE export joined on the per-agent SPIFFE actor. Doc, not a
  combiner.

Decisions so far: **D2** = extend receipt vocabulary additively (v1.1 shipped in
AL-0.5). **D3** = approvals resolvable from both the AL control plane and the
operator shell's `:approve`. **D4** = default-deny ToolPolicy applies to every
session (human-interactive included); HITL-instead-of-confirm remains
agent-attached-only; NullGatekeeper installs unchanged. D1 (embed as library)
per plan. Observability-UI upgrade deferred by Amit.

---

## TL;DR

`ac connect <host>` works for **both** connection styles, chosen per server from
each host's own `via:` in `config/inventory.yaml`:

- **Via bastion** (`via.from: bastion1`) — SSH tunnel → WinRM over loopback →
  Windows **SSPI**. The sanctioned, robust path.
- **Direct / VPN** (`via.from: local`) — connects straight to the target's real
  address, **no bastion**, using **pure-Python NTLM**.

The NTLM implementation is selected automatically (`auth.ntlm_provider: auto`,
the default). No environment variables, no per-host tuning across a large fleet.

On top of that: a **campaign** layer (`ac campaign`) fans one reviewed brief out
across many hosts' live sessions, and the `ac connect` window is a **prompt** on
the host that holds the session at the last authenticated hop if the final leg
fails.

---

## Where each path stands

| Path | State | Evidence |
|---|---|---|
| **SSH through a bastion chain** (Linux / Unix / AIX) | **Verified in production** | End to end against `10.0.0.36` (aix-target01, AIX 7.3). `$SSH_CLIENT` on the target reported the *hop's* address, proving `direct-tcpip` forwarding worked against something other than a test double. Re-confirmed 2026-08-20 against `10.0.0.43` (app-prod01, CHG prod) via `bastion-prod` — see [that session](#field-session-2026-08-20--app-prod01-tms4saxwayapp01-chg-prod) |
| **Direct WinRM** (`via.from: local`, no bastion) | **Verified in production** | `win-target01-dev` = `win-target01.example.net` / `10.0.0.136`, Windows Server 2022, login `prod\operator`. Connect, `ac verify` identity, `ac exec`, `ac run windows-health` all succeeded |
| **WinRM through an SSH bastion** | Implemented, unit-tested, **not proven live** | The tunnel and PSRP layers are exercised separately; the combination has not run against real hardware |
| **Nested Windows → Windows** (`Invoke-Command` from a jump server) | Implemented, unit-tested, **not proven live** | The flagship topology in every diagram, and the least proven. Verify with `ac probe --deep` before relying on it |
| **RDP handoff** (`ac rdp`) | Implemented | Windows-only; not covered by the offline suite (it launches a GUI) |
| **Campaigns** | Implemented, unit-tested | `tests/test_campaign.py`: parsing, offline planning, concurrent dispatch with a fake client, skip-on-no-session, per-target isolation |

---

## Field session 2026-08-20 — app-prod01 (AppProd01, CHG prod)

First live run against the CHG prod Axway estate through `bastion-prod`.
**Read operations verified end to end.** Three defects surfaced; all three were
invisible to the offline suite, and two of them only ever fire on the *agent*
path, which is why a year of operator-driven use never hit them.

Evidence — session `SES-000046`, route `local -> bastion-prod (ssh) ->
app-prod01-bastion (ssh)`:

```
$ ac exec app-prod01-bastion -- 'hostname; whoami; uptime'
exit 0 in 0.25s on app-prod01-bastion via ssh
app-prod01
operator
 19:49:47 up 300 days, 13:44,  1 user,  load average: 2.36, 2.40, 2.22
```

### Defects found and fixed

| # | Where | Symptom | Cause | Fix |
|---|---|---|---|---|
| A | `config/inventory.yaml` | Target leg failed `password authentication failed`; looked exactly like a wrong password | `domain: prod` on a **non-AD Linux** host, so `config.py:197` qualified the login to `prod\operator`, which sshd rejected. The bastion hop has no `domain:`, so it authenticated — hence the FALLBACK | Removed `domain:` from both prod Axway targets. `ac shell` (which uses the *bare* `target.user`, `cli.py:1413`) logged in fine, which isolated it |
| B | `credentials.py` CredUI | `credential dialog failed ((87, 'CredUIPromptForCredentials', 'The parameter is incorrect.'))` — the dialog **never rendered**, and the leg reported as an auth failure | Caption was `"access-control: " + hop label`; the label embeds the node's inventory `description`, giving **174 chars against `CREDUI_MAX_CAPTION_LENGTH` = 128**. Windows rejects the whole call rather than truncating. The bastion's caption is 45, so only the second dialog failed | Clamp caption to 128 and message to 1024 |
| C | `credentials.py` `TerminalPrompter` | `ac connect` died ~3 s in with no prompt, no dialog and no error; audit stopped after `hop.auth ... publickey` | `available()` tests `sys.stdin.isatty()`, which is **not proof anyone can answer** — an agent shell can hand over a tty already at EOF. `getpass` raised `EOFError`, mapped to "cancelled at the prompt", process exited | On `EOFError` (not `KeyboardInterrupt`) fall back to the Windows dialog; raise a loud, specific error when no dialog exists |

### Harness limits — not bugs, but they shape how sessions get opened

- **The `!` prefix and an agent's Bash tool cannot host an interactive prompt.**
  Stdin is at EOF, so both the password prompt *and* the operator shell die on
  first read. Fix C makes the *credential* half work there (dialog on the
  desktop); the typeable prompt still requires a real terminal window.
- Two workable arrangements, and they trade off directly:
  **(A)** operator runs `ac connect` in a real terminal → in-window prompts plus
  a prompt naming the machine; the agent attaches by host id and shares the
  session id. **(B)** agent runs it with `AC_PROMPTER=windows --no-shell` →
  operator answers desktop dialogs, no prompt window exists, everything is
  driven through the agent. **A is preferred**; B was only used here to keep the
  work inside one window.
- Attachment is verifiable: `ac exec` finds the existing session or refuses —
  it never opens its own. `session.open` and every `COMMAND_EXECUTE` share one
  `sessionId` and `agentId` in the JSONL trail.

### Follow-ups owed from this session

| Item | Why |
|---|---|
| ~~`.gitignore` `*credential*` excludes `src/access_control/credentials.py`~~ **Done** | The blanket pattern was narrowed to credential material (`credentials.json`, `*credentials.y*ml`, `*credentials.txt`) and `credentials.py` is now tracked and committed |
| Audit the estate for `domain:` on non-Windows nodes | Defect A is latent on `AppProd02` and any future Linux entry copied from a Windows one. `ac doctor` could flag `domain:` on `kind: linux` |
| Regression tests for B and C | Both are pure-logic: caption length clamp, and EOF-to-dialog delegation. Neither needs a host |
| `ac timeline SES-000046` reports "no audit trail" | The log file exists at the path `ac status` prints; the lookup does not find it by session id |

---

## Change 2026-08-31 — concurrent-session identity

Prompted by a design question rather than a failure: *can ten agents work ten
servers independently?* Runtime isolation was already sound — each `ac connect`
is its own process, port, descriptor and engine — but **identity was not**.

`context._next_sequence` guarded a file read-modify-write with a
`threading.Lock`, which serialises threads inside one process and nothing at all
across ten. Three consequences, none of which the offline suite could see
because it never ran two processes at once:

- Two sessions could take the same `SES-nnnnnn`.
- Two starting in the same second could take the same `trace_id` — which **names
  the log file**, so their audit trails interleaved in one `.jsonl`.
- Without an explicit id, two independent agents could take the same
  `AGT-<date>-<seq>`. `audit.default_agent_id()` was worse: every agent on one
  host was `claude-code@HOST`.

Fixed by removing the shared state rather than locking it — ids now carry a
random 6-hex suffix and need no coordination (`SES-3f9a1c`, trace
`20260812T091520Z-3f9a1c`). `_next_sequence` and the `state/*.seq` files are
gone; the code is smaller than before. `ac connect --agent-id` was added so a
run can be *named*, not merely unique. See [B-16 and C-12](BugFixNchange.md).

Both arrangements now work with no configuration: one operator across ten
servers (share an `AC_AGENT_ID`, separate by `sessionId`), or ten agents each
owning one server (`--agent-id` per window — a shared `AC_AGENT_ID` in project
settings would be actively wrong there).

Unproven at scale: no test yet opens ten real concurrent sessions. The
collision test spawns 50 identities inside one second, which covers the id
generation but not the daemon under genuine parallel load.

---

## The NTLM problem, and how it is solved

Worth keeping, because it cost a day and looks exactly like a wrong password.

This workstation is **WORKGROUP** (not domain-joined) and Group Policy sets
`RestrictSendingNTLMTraffic = 2` ("Deny all outgoing NTLM") with an allow-list
(`ClientAllowedNTLMServers`) that has **no `HTTP/` SPN** for the corporate targets.

Proven consequences:

- **Direct WinRM via Windows SSPI fails** with `SEC_E_LOGON_DENIED`
  (`WinError -2146893044` / `0x8009030C`), raised **locally** inside
  `initialize_security_context` — *before any packet is sent*. The credential is
  correct; it looks like it is not.
- **Pure-Python NTLM** (spnego `NegotiateOptions.use_ntlm`) does **not** consult
  the LSA allow-list, so it authenticates fine.
- **The bastion path is unaffected**, because NTLM then originates to
  `127.0.0.1` (loopback), which the policy does not block.

`auth.ntlm_provider: auto` resolves this from each server's own route, and the
resolved value is recorded in a `winrm.ntlm_provider` audit event.

**Note this is a deliberate step around a corporate control.** The compliant path
is the bastion. Worth a policy conversation before direct routes become the norm
— see [docs/SECURITY.md §3.5](docs/SECURITY.md#35-ntlm-provider-selection).

---

## What exists today

| Area | State |
|---|---|
| Declared route graph, load-time validation, environment boundaries | Complete |
| In-process tunnels, forwarding-capability probe | Complete |
| Zero-storage credentials, per-hop prompting, MFA passthrough, redaction | Complete |
| SSH transport (chained `direct-tcpip`, key+password, host-key policy) | Complete, production-proven |
| WinRM/PSRP, nested `Invoke-Command`, NTLM provider selection, wedge recovery | Complete; nested leg unproven live |
| Operation catalogue, expectations, failure diagnostics, hints, resume-from-step | Complete |
| Task briefs, offline validation, preflight including the identity gate | Complete |
| Campaigns | Complete, bounded by human-opened sessions |
| Session daemon, operator prompt, hop fallback, `ac reload` | Complete |
| Audit trail, timeline, per-session and per-operation reports, retention | Complete |
| Command deny-list (two tiers, comment-aware) | Complete |
| Interactive handoff (`ac rdp`, `ac shell`, `ac tunnel`) | Complete; RDP launches are not audited |
| Documentation | Complete as of 2026-08-17 |
| CI, linting, type checking, coverage gates | GitHub Actions runs the suite on Ubuntu + Windows (2026-08-31); lint/type/coverage still **none** |
| RBAC, SSO, credential broker, unattended runs | **Not built, by design** |

---

## Improvements needed

Ordered. Full detail and suggested fixes in
[BugFixNchange.md](BugFixNchange.md); readiness impact in
[docs/production-readiness.md](docs/production-readiness.md).

### 1. Before this is used for production change work

| # | Item | Why |
|---|---|---|
| 1 | **Commit the repository** (F-23) | There is no history at all. Every review, rollback and audit process the docs recommend assumes version control, and `operations.yaml` is executable content |
| 2 | **Apply the hardening checklist** ([SECURITY.md §10](docs/SECURITY.md#10-production-hardening-checklist)) | `AC_HOST_KEY_POLICY=strict`, `context.environment` on every node, a bounded idle timeout, `AC_ALLOW_ENV_CREDENTIALS` unset |
| 3 | **Adopt the agent permission policy** ([guardrails §8.2](docs/CLAUDE_PRODUCTION_GUARDRAILS.md#82-tool-permission-policy-claude-code-settingsjson)) | Including denying a general shell — that bypasses every control in the design |
| 4 | **Ship the JSONL trail to the SIEM** and alert on the P1 signals | `COMMAND_BLOCKED`, failed `target.identity`, `HOST KEY MISMATCH` |

### 2. Control gaps worth building

| # | Item | Why |
|---|---|---|
| 5 | **An interactive approval gate** (F-01) | `--confirm` is a flag the caller passes. Nothing proves a human agreed at that moment — the single highest-value change for agent deployments |
| 6 | **Extend `--ops` scoping to `run_command`** (F-02) | A "restricted" session still permits arbitrary ad-hoc commands. Today's only mitigation is not handing an agent a session at all |
| 7 | **Audit RDP launches** (F-03) | `RDP_LAUNCH` is declared and never emitted; an interactive production session leaves no record |
| 8 | ~~**An absolute session lifetime** (F-04)~~ **Done 2026-09-01** — `ac connect --max-lifetime` | Activity refreshes the idle timer indefinitely |

### 3. Correctness and hygiene

| # | Item |
|---|---|
| 9 | ~~Fix `ac tunnel --port`, silently ignored, with a misleading warning (F-07)~~ **Done 2026-08-31** |
| 10 | ~~Run `postcheck:` in a brief, or reject the key so nobody relies on it (F-08)~~ **Done 2026-08-31** |
| 11 | Apply `logging.level` or remove it (F-05) |
| 12 | Rotate `transport.log` and `errors.log` (F-06) |
| 13 | Add CI running `uv run pytest` (**done 2026-08-31**, Ubuntu + Windows), plus ruff and mypy (still open — F-20, F-21, F-22) |
| 14 | Remove the stray files: `New Text Document.txt`, `disconnect`, `config/inventory copy.yaml`, `config/inventory_Orig_Copy.yaml` (F-24) |
| 15 | Wire up or delete the dead code — `discard_after_auth`, `direct_allowed`, three unused event constants, `extra_rules` (F-14 … F-18; F-19 resolved 2026-08-31) |

### 4. Verification owed

| # | Item |
|---|---|
| 16 | **Prove the nested Windows→Windows leg against real hardware** (F-26) — `ac probe --deep`, then a read-only operation, then a gated one |
| 17 | Prove WinRM *through a bastion* end to end (F-27) |
| 18 | Record the evidence for both in [docs/guides/testing.md](docs/guides/testing.md) |

### 5. Decisions to take deliberately, not by accretion

| # | Item |
|---|---|
| 19 | **Credentials at scale.** A broker or vault is the only way past one human-opened session per host. It changes the threat model fundamentally; nothing in the current security assessment carries over unreviewed |
| 20 | **Output classification** for regulated estates — collected server logs currently reach the model unfiltered |
| 21 | **Direct-route policy** — how widely the pure-Python NTLM path is acceptable, with the NTLM policy owner |

---

## Housekeeping notes

- `win-target01-dev` carries the tag `windows-2019` but is Server 2022. Cosmetic;
  nothing binds on it today.
- `config/inventory.yaml` keeps the `appwin-*` / `applnx-*` route-selection
  examples commented out as documentation. `appwin-qa-vpn` used a YAML `<<:`
  merge from `appwin-qa-bastion`: uncommenting one without the other gives an
  "undefined alias" error. Uncomment both, or make the entry standalone.
- The two Axway field reports moved to [docs/reports/](docs/reports/) in the
  documentation audit. They analyse customer systems, not this project.
- Audit trails and session descriptors live under
  `%LOCALAPPDATA%\access_control\`, deliberately outside this OneDrive-synced
  repository.

---

## Where to look next

| Question | Document |
|---|---|
| How is it built? | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| What does every setting do? | [docs/CONFIGURATION.md](docs/CONFIGURATION.md) |
| Is it safe? What must change first? | [docs/SECURITY.md](docs/SECURITY.md), [docs/production-readiness.md](docs/production-readiness.md) |
| What is broken or missing? | [BugFixNchange.md](BugFixNchange.md), [docs/gap-analysis.md](docs/gap-analysis.md) |
| How do I run it? | [docs/guides/runbook.md](docs/guides/runbook.md) |
| How do I deploy Claude against it? | [docs/CLAUDE_PRODUCTION_GUARDRAILS.md](docs/CLAUDE_PRODUCTION_GUARDRAILS.md) |
