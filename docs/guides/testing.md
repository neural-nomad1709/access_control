# Testing

## Running

```powershell
uv run pytest                    # everything
uv run pytest -q tests/test_e2e.py   # just the end-to-end loops
uv run pytest --cov=access_control --cov-report=term-missing
```

Every test runs **fully offline** — no bastion, no target, no corporate network.
The SSH layer is exercised against a real SSH server started in-process, not
against a mock.

## What is covered

| File | Tests | Covers |
|---|---:|---|
| `test_config.py` | 44 | Inventory and catalog parsing, `via:` compilation, validation, host_id/tag binding, variable resolution |
| `test_route.py` | 14 | Every route shape and every rejected topology |
| `test_routegraph.py` | 64 | Declared edges, resolution, mandatory ports, pre-established tunnels, environment boundaries, domain qualifying, agent identity, logging config |
| `test_security.py` | 65 | Redaction, the command deny-list, credential handling |
| `test_engine.py` | 58 | Templating, exit-code parsing, expectations, gating, dry run, failure diagnosis, the operation report, canonical actions, timeline |
| `test_daemon.py` | 19 | Session descriptors and the loopback protocol, over real sockets |
| `test_brief.py` | 47 | Task brief parsing and validation, preflight checks, host-identity matching, check ordering |
| `test_campaign.py` | 11 | Campaign parsing, offline planning and retargeting, concurrent dispatch with a fake client, skip-on-no-session, per-target isolation |
| `test_e2e.py` | 18 | Two full cycles, the agent path, chain failure modes, hop fallback, forwarding detection, probe reporting — over real SSH |
| **Total** | **340** | |

Counts move as tests are added; `uv run pytest` is the authority.

## Why the SSH server is real

`tests/sshfake.py` is an actual SSH server built on Paramiko's server API, not a
mock. Mocking would prove nothing about the part most likely to break: the
multi-hop chain itself. What the tests therefore exercise for real:

- a genuine SSH handshake and host-key verification,
- `publickey`-then-`password` multi-factor — the server returns
  `AUTH_PARTIALLY_SUCCESSFUL` exactly as OpenSSH does with
  `AuthenticationMethods publickey,password`,
- `exec` with real exit statuses on both stdout and stderr,
- `direct-tcpip` forwarding, so the second hop genuinely travels through the
  first.

This caught a real bug that unit tests would not have: `PartialAuthentication` is
not re-exported at Paramiko's top level in 5.0, so the key+password path — the
one the production bastion uses — raised `AttributeError` instead of continuing
to the password stage.

## The two end-to-end loops

PLAN.md asks for at least two complete cycles before the product is called ready.

### Loop 1 — happy path

`TestLoopOneHappyPath::test_full_cycle`

1. **Connect** through the bastion to the target. Asserts a distinct password
   prompt appeared for *each* hop, that the two prompt labels differ, and that
   the bastion actually forwarded a connection onward to the target's port.
2. **Multi-factor** — asserts the bastion recorded `["publickey", "password"]`,
   and the target `["password"]`.
3. **List operations** — the agent discovers what the catalog permits.
4. **The gate holds** — a gated operation is refused, the refusal contains the
   fully-rendered command (`apt-get install -y myapp`, not `{{package}}`), and
   nothing ran.
5. **Approved, it runs** — and the fake server records the install.
6. **Verify** — a second operation confirms the state.
7. **Report and close** — status before teardown, then credentials wiped.
8. **Audit** — the trail reconstructs the hops in order, every step in order,
   with matching agent and session ids; it exists on disk with a markdown
   summary; and **neither password appears anywhere in it**.

### Loop 2 — failure and recovery

`TestLoopTwoFailureAndRecovery::test_full_cycle`

This is the loop the whole design exists for.

1. The application service is stopped before the run — a fault the agent must
   find.
2. **The operation fails** at `service-state` with exit 3, and stops there;
   subsequent steps do not run.
3. **It returns a diagnosis, not just a failure** — the nominated log was
   collected and contains the real cause (`config file /etc/myapp.conf not
   found`), the exit-code-specific hint is attached, and `next_action` tells the
   agent to investigate.
4. **The agent remediates** — investigates with a read-only command (no
   confirmation needed), then repairs with a state-changing one (confirmation
   required, and an unconfirmed variant is still refused).
5. **Re-runs only the failed step** via `start_at`, and succeeds.
6. **Closes cleanly** — the failure remains in the record; the report does not
   pretend the run was clean.

### Also covered end-to-end

- `TestAgentPath` — the production shape: the operator connects, then an agent
  drives the session over the loopback socket with only a host id and a token,
  never seeing a credential. Preview → refusal → approval → run → fetch a log →
  close.
- `TestChainFailures` — a wrong bastion password (and that the rejected
  credential is *not* retained), an unreachable bastion, a bastion refusing
  forwards, and a changed host key being fatal.

## Live verification against real hardware (2026-08-12)

The SSH half has been run end to end against **`10.0.0.36` (aix-target01, AIX
7.3)** through a real multi-hop chain. The decisive evidence: `$SSH_CLIENT` on
the target reported `10.0.0.36 57049 22`, meaning the second SSH session
genuinely arrived *from the hop* rather than from the client machine — the
`direct-tcpip` forwarding mechanism working on something other than a test
double.

Three defects surfaced that no offline test had:

| Found | Why offline tests missed it |
|---|---|
| `rm` ungated on Unix while `Remove-Item` was gated on Windows | The deny-list was reviewed against Windows examples; nobody ran a Unix delete |
| `ac disconnect` raced its own reply and returned a connection error | Timing-dependent; the in-process test happened to win the race |
| `linux-health` returned an empty disk section on AIX (`df` has no `-h`) | No AIX in CI, and `2>/dev/null` hid the failure |

The third is the instructive one: piping stderr to `/dev/null` turned a hard
failure into a silently missing section, on exactly the platform PLAN.md calls
out. Prefer probing for a flag over hiding the error.

Regression tests were added for all three
(`test_security.py::test_posix_file_and_process_changes_need_confirmation`,
`test_daemon.py::test_close_returns_the_report_before_tearing_down` and its
repeat-run companion).

### Re-verified after the connectivity redesign

The same host, with the explicit route graph, per-run identity and canonical
action records in place:

```
13:54:30  SESSION_START        local -> aix-via-hop  local -> aix-target01 (ssh) -> aix-via-hop (ssh)
13:54:31  SSH_CONNECT          local -> aix-target01  10.0.0.36:22 (0.81s)
13:54:32  SSH_CONNECT          aix-target01 -> aix-via-hop  10.0.0.36:22 (0.8s)
13:54:41  SCRIPT_EXECUTE       local -> aix-via-hop  linux-health/snapshot (0.19s)
13:54:42  COMMAND_EXECUTE      local -> aix-via-hop  df -k | head -3 (0.3s)
13:54:43  COMMAND_BLOCKED      local -> aix-via-hop  rm /tmp/nope
13:54:44  SESSION_END          local -> aix-via-hop  closed
```

That one output covers gaps 6, 7 and 9 at once: distinct identity per run
(`AGT-20260812-3f9a1c` / `SES-3f9a1c`), canonical `source -> target` records
including the refusal, and a readable execution trace with timings.

## Live verification of the Windows path (2026-08-13)

Direct WinRM has since been verified end to end against a live **Windows Server
2022** host (`win-target01-dev`, reached with `via: {from: local}` — no bastion):

- connect as `prod\operator`, with `ntlm_provider: auto` resolving to the
  pure-Python provider because the leg is direct;
- `ac verify` → `target.identity` confirmed;
- `ac exec` (`hostname`, `whoami`, OS caption) and
  `ac run <host> windows-health` both succeeded;
- the transport-wedge rebuild path was exercised (a desynced NTLM message-seal
  producing an empty `Bad HTTP response … Code: 400`, recovered transparently).

Two findings worth carrying forward:

| Found | Lesson |
|---|---|
| Windows SSPI failed locally with `SEC_E_LOGON_DENIED` on a direct route, looking exactly like a wrong password | A client-side *Restrict NTLM outgoing* policy fails **before** any packet is sent. `ntlm_provider: auto` now resolves this per route |
| A double-quoted remote script had `$env:` expanded by the *local* shell before sending, producing a malformed command that triggered the wedge | Single-quote anything you pass to `ac exec` on Windows |

## What these still cannot cover

**The nested Windows-to-Windows leg.** PSRP through a Windows jump server needs
real hardware on both ends; there is no in-process equivalent of a WinRM server.
That path is implemented and unit-tested but has **not** run against live
hardware. Verify it against the live environment:

```powershell
# 1. What actually answers, per hop
uv run ac probe target1 --deep

# 2. Proves the full Local -> Bastion -> Jump -> Target chain executes
uv run ac connect target1
uv run ac exec target1 -- '$env:COMPUTERNAME; (Get-CimInstance Win32_OperatingSystem).Caption'

# 3. A read-only operation
uv run ac run target1 windows-health

# 4. The failure path: install a package that does not exist and confirm the
#    collected MSI log and hint come back
uv run ac run target1 install-package -p package=does-not-exist.msi --confirm

# 5. Interactive handoff, and that the staged credential is removed afterwards
uv run ac rdp target1
cmdkey /list        # must not list TERMSRV/127.0.0.1:<port>
```

Record the results in this file when that environment is available.

## Security assertions

These are the ones a regression would be most costly:

- A registered secret never appears in an `ExecResult`, an audit record, or an
  exception message (`test_security.py::TestRedaction`).
- The end-to-end audit trail on disk contains neither the bastion nor the target
  password (`test_e2e.py`).
- A rejected password is discarded rather than retried
  (`test_e2e.py::test_wrong_bastion_password_does_not_retain_the_credential`).
- Every hop is prompted separately; a credential is not shared between them
  (`test_security.py::test_each_node_is_prompted_separately`).
- An MFA challenge reaches the operator instead of being answered from cache
  (`test_security.py::test_challenge_asks_the_operator_for_an_otp`).
- Blocked commands cannot be run even with confirmation, over the wire
  (`test_daemon.py::test_blocked_command_is_refused_even_with_confirmation`).
- A wrong session token is rejected (`test_daemon.py::test_a_wrong_token_is_rejected`).

## Regression tests for bugs found while building

Each of these was a live defect, not a hypothetical:

| Bug | Test |
|---|---|
| `paramiko.PartialAuthentication` does not exist at top level in 5.0, breaking key+password | `test_e2e.py::TestLoopOneHappyPath` (asserts the auth sequence) |
| The permission refusal rendered the preview without the operator's parameters, so it raised "missing parameter" instead of showing the commands | `test_e2e.py` step 3; `test_engine.py::test_gated_operation_refuses_without_confirmation` |
| `\breboot\b` matched the word inside a comment describing exit code 3010 | `test_security.py::test_a_comment_mentioning_reboot_is_not_an_instruction` |
| `\b/x\b` never matches ` /x ` — the boundary before `/` fails after a space | `test_security.py` (`msiexec /x` case) |
| Expectations were not templated, so `stdout_contains: '{{package}}'` could never match | `test_engine.py::test_expectations_are_templated` |
| Dry run enforced policy and reported a gated step as "blocked" instead of showing what would happen | `test_engine.py::test_dry_run_reports_gating_instead_of_blocking` |
| Rich markup ate `[math]::Round` in previews, so the operator approved text that differed from what would run | `cli._raw` (`markup=False`); exercised by `ac preview` |
| A malformed line in `known_hosts` raised `InvalidHostKey` and made every connection impossible | `test_e2e.py::test_changed_host_key_is_fatal` exercises the load path |

## Writing new tests

- **Offline by default.** If a test needs a network, it belongs in the live
  verification list above, not in `pytest`.
- **Assert on behaviour the operator depends on**, not on internals. "The
  refusal names the command that would run" is worth a test; "the method returns
  a dict" is not.
- **Use `FakeSession`** (in `conftest.py`) for engine-level tests, and
  `FakeSSHServer` (in `sshfake.py`) when the chain itself is what is under test.
- **Never put a real credential in a fixture**, even a fake-looking one. The
  end-to-end tests use obviously-synthetic values and then assert they are absent
  from the audit trail.

## Known gaps in the suite

Honest about what is *not* asserted, so nobody mistakes a green run for full
coverage:

| Gap | Consequence |
|---|---|
| No WinRM/PSRP server double | `transport/winrm.py`, the nested leg, NTLM provider selection and wedge recovery are exercised only at unit level |
| No CI pipeline in the repository | The suite runs when someone remembers. There is no `.github/workflows`, no pre-commit hook, and no coverage gate |
| No coverage threshold enforced | `--cov` is available but nothing fails on a drop |
| No linter or type checker configured | No ruff/mypy config, despite the code being fully annotated |
| No RDP path test | `transport/interactive.py` is Windows-only and launches a GUI |
| `postcheck:` in a brief | Parsed but never executed, so there is nothing to test |

These are tracked in [../gap-analysis.md](../gap-analysis.md).
