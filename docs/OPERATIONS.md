# Operations

Running the tool day to day: development, production use, monitoring, logging,
backup and recovery, maintenance, and upgrades.

Symptom-by-symptom troubleshooting lives in
[guides/runbook.md](guides/runbook.md#part-2--troubleshooting-by-symptom); this
document is about running the thing, not fixing one error.

---

## 1. Operating model

There is no service to run. A "deployment" is one operator, one workstation, one
checkout of this repository. Two people using the tool are two independent
clients with their own credentials and their own audit trails.

The unit of work is a **session**: one authenticated path to one host, held open
in the terminal where the passwords were typed, driven by any number of thin
clients (yours, or an agent's).

```
Terminal 1                          Terminal 2 (or the agent)
──────────                          ─────────────────────────
uv run ac connect win-app01         uv run ac verify win-app01 --expect-hostname WIN-APP01
  → prompts per hop                 uv run ac run    win-app01 windows-health
  → holds the session               uv run ac timeline <session-id>
  → gives you a prompt              uv run ac disconnect win-app01
```

---

## 2. Running in development

### 2.1 Setup

```powershell
uv sync --extra dev
uv run ac doctor
uv run pytest              # 340 tests, entirely offline
```

### 2.2 The offline loop

Everything below connects to nothing, so it is the fastest way to iterate:

```powershell
uv run ac routes                                  # every declared edge
uv run ac routes <host>                           # resolve one, verbose
uv run ac hosts                                   # do all routes resolve?
uv run ac ops                                     # the catalogue
uv run ac preview <host> <operation> -p k=v       # exact rendered commands
uv run ac run <host> <operation> -p k=v --dry-run # whole pipeline, nothing executed
uv run ac brief validate config\briefs\x.yaml
uv run ac campaign validate config\campaigns\x.yaml
```

`ac run --dry-run` works with **no live session at all** — it builds an offline
engine, renders every step and reports which ones policy would gate.

### 2.3 Iterating on an operation without re-authenticating

Reconnecting costs a password at every hop. Don't.

```powershell
uv run ac reload <host>       # re-reads operations.yaml into the live session
```

It reports what was added and removed. It is **refused if the host's route
changed** in `inventory.yaml`, because the live connection would no longer match
the config — that case genuinely needs a reconnect.

Editing the tool's *source* also needs a reconnect: the running session holds the
code it started with. "The fix didn't work" is usually "the fix isn't loaded".

### 2.4 Testing

```powershell
uv run pytest                                          # all
uv run pytest tests/test_e2e.py                        # the two end-to-end loops
uv run pytest -k security                              # deny-list and redaction
uv run pytest --cov=access_control --cov-report=term-missing
```

See [guides/testing.md](guides/testing.md) for what each file covers and what the
suite deliberately cannot cover.

---

## 3. Running in production

### 3.1 Before the change window

Do all of this hours earlier. None of it needs the network or a credential.

```powershell
uv run ac doctor
uv run ac routes <host>
uv run ac brief validate config\briefs\tonight.yaml
uv run ac brief show     config\briefs\tonight.yaml     # a human approves this
```

A brief that fails validation at 22:05 costs you the window; the same failure at
15:00 costs a minute.

Then, once, with the network:

```powershell
uv run ac probe <host> --deep
```

Look for `tcp forwarding: yes` on every bastion and an open automation port on
the target. `--deep` is the only honest test of the jump → target leg.

### 3.2 In the window

```powershell
# Terminal 1 — yours. Prompts per hop. Leave it open.
uv run ac connect <host> --ops install-package,windows-health --idle-timeout 7200

# Terminal 2 — you, or the agent
uv run ac verify <host> --expect-hostname <ITS-REAL-NAME>
uv run ac brief run config\briefs\tonight.yaml --confirm
uv run ac timeline <session-id>
uv run ac disconnect <host>
```

Production discipline, in priority order:

1. **`ac verify` with `--expect-hostname` before anything runs.** Every hop past
   the first arrives over a local port forward, and a port number carries no
   identity. A stale forward produces a session that works perfectly against the
   wrong server.
2. **Scope the session with `--ops`.** It then refuses anything else, even if
   `operations.yaml` is edited underneath it.
3. **Preview before approving.** `ac preview` renders the real commands.
4. **Use `--start-at` after a failure**, not a full re-run — repeating a
   destructive step is sometimes actively harmful.
5. **Set a bounded `--idle-timeout`.** `0` means an authenticated session with
   live credentials lives until the window closes.
6. **Disconnect explicitly.** It prints the final status and wipes credentials
   immediately.

### 3.3 Fleet work — campaigns

```powershell
# one terminal per host, each authenticated by a human
uv run ac connect host-a
uv run ac connect host-b

# then, from anywhere
uv run ac campaign validate config\campaigns\qa-health-sweep.yaml   # offline + session status
uv run ac campaign run      config\campaigns\qa-health-sweep.yaml --parallel 4
```

Campaigns handle **no credentials**. They attach to sessions that already exist;
hosts without one are reported and skipped, never connected to. That is the
current ceiling on fan-out: a human has to open each session. See
[STATUS.md](../STATUS.md) for where that is heading.

### 3.4 What production use does *not* support

- **Unattended or scheduled runs.** An operator must be present, because nothing
  is stored. Use a PAM product or a vaulted service account if you need 03:00
  patching with nobody watching.
- **Multi-user approval workflow.** One operator, one session, one approval.
- **Idempotency.** Running an operation twice runs it twice.

---

## 4. Monitoring and alerting

### 4.1 What to collect

Point `logging.path` (or `AC_LOG_DIR`) at a directory your collector reads:

```yaml
logging:
  enabled: true
  path: D:\Agent\Logs
  retention_days: 30
  level: INFO
```

Every `*.jsonl` file is one session. Records already use canonical field names —
`timestamp`, `agentId`, `sessionId`, `action`, `source`, `target`, `result` — so
they drop into a SIEM without a transform step.

### 4.2 Signals worth alerting on

| Signal | Filter | Why |
|---|---|---|
| Blocked command | `action == "COMMAND_BLOCKED"` | An agent or operator proposed something on the never-run list |
| Refused approval | `action == "PERMISSION_REQUEST" && result == "BLOCKED"` | A gated operation was attempted without approval |
| Wrong host | `event == "preflight" && result == "FAILURE"` with a failing `target.identity` check | The single most dangerous failure mode |
| Bastion bypass | `event == "winrm.direct"` | A route connected with no bastion at all |
| NTLM policy bypass | `event == "winrm.ntlm_provider" && provider == "python"` | The pure-Python provider stepped around "Restrict NTLM outgoing" |
| New host key | `event == "host_key.new"` | Trust-on-first-use happened; verify the fingerprint |
| Unreadable known_hosts | `event == "host_key.unreadable"` | Host-key checking degraded |
| Hop failure | `event == "hop.failed"` | Reachability or authentication problem |
| Session degraded | `event == "session.degraded"` | The target leg failed; the session is held at a hop |
| Errors | `event == "error"` | Any recorded failure |
| Session never closed | a `session.open` with no matching `session.close` | Terminal killed, or the process died — credentials were not wiped by the normal path |
| Destructive operation | `event == "operation.end"` where the operation is marked destructive | Change tracking |

`ac audit` lists recent sessions with `status: incomplete` for exactly the
"never closed" case.

### 4.3 Live inspection

```powershell
uv run ac status                    # every live session: host, session id, pid, agent
uv run ac status <host>             # route, connected, steps ok/failed, idle timer, audit file
uv run ac status <host> --json      # + tunnels, authenticated nodes, degraded state
uv run ac audit                     # recent sessions and how each ended
uv run ac timeline <session-id>     # ordered actions with durations
```

At the `ac connect` prompt itself: `:status`, `:where`, `:route`.

### 4.4 What is not instrumented

No metrics endpoint, no tracing exporter, no built-in alerting, and no health
check beyond `ac doctor`. Alerting is expected to come from ingesting the JSONL.

---

## 5. Logging

| File | Content | Rotation |
|---|---|---|
| `<log dir>/<trace_id>.jsonl` | One session's audit trail, one JSON object per action, fsynced | Pruned by `retention_days` |
| `<log dir>/<trace_id>.md` | Human summary written on close: hops, timeline, step table, errors | Pruned by `retention_days` |
| `<log dir>/<session>-NN-<op>.md` | Per-operation shareable report | Pruned by `retention_days` (matches `*.md`) |
| `<log dir>/transport.log` | Paramiko / pypsrp / spnego, redacted | **Never rotated — see below** |
| `<log dir>/errors.log` | Tracebacks of unexpected failures | **Never rotated — see below** |

Pruning of `*.jsonl` and `*.md` older than `retention_days` runs when a session
starts, and never raises — a failure to prune must not stop a session.

> **Operational gap:** `transport.log` and `errors.log` grow without bound and are
> not covered by retention. They are append-only and usually small, but on a
> machine that runs the tool constantly they should be rotated externally
> (logrotate, or a scheduled truncate). Tracked in
> [gap-analysis.md](gap-analysis.md).

### 5.1 Log content and sensitivity

Secrets are scrubbed everywhere. **Captured server output is not** — an audit
trail can contain event-log excerpts, installer logs and command output. Treat
the log directory as internal data:

- keep it outside the repository (the default already is),
- keep it off synced folders,
- restrict its ACLs to the operator,
- forward it to the SIEM rather than emailing files around.

### 5.2 Turning it down or off

```yaml
logging:
  enabled: false      # keeps the in-memory trail so `ac status` works; writes nothing
```

Not recommended outside testing: `ac audit` and `ac timeline` then have nothing
to read, and there is no record of what was run.

---

## 6. Backup and recovery

### 6.1 What is worth backing up

| Item | Backup | Recovery |
|---|---|---|
| `config/*.yaml` (inventory, operations, briefs, campaigns) | **Version control.** This is the only irreplaceable state | `git checkout` |
| `<log dir>/*.jsonl` and `*.md` | Copy to your evidence store before retention prunes them | Read-only artefacts; nothing to restore into |
| `~/.ssh` keys and `known_hosts` | Your existing key-management process | Restore the files; re-verify fingerprints |
| `<root>/state/*.seq` | Not worth backing up | Counters restart from 0; ids stay unique because `trace_id` carries a UTC timestamp |
| `<root>/sessions/*.json` | **Never.** Ephemeral tokens | Delete stale ones |
| `.venv` | No | `uv sync` |

### 6.2 Recovery scenarios

| Situation | Action |
|---|---|
| **The `ac connect` window was closed or crashed** | Nothing to recover — credentials existed only in that process. Reconnect. The audit trail on disk is complete up to the last action (every record is fsynced) |
| **A stale descriptor points at a dead process** | `attach()` removes it automatically on the next command. To force it: delete `<root>/sessions/<host>.json` |
| **The session idled out mid-task** | Credentials were wiped. Reconnect, `ac verify`, then re-run the failed operation with `--start-at <step>` rather than from the top |
| **An operation failed partway** | Read the report (`summary_file`), fix the cause, then `ac run <host> <op> --confirm --start-at <failed-step>`. The report names the exact command |
| **A session is held at a hop (degraded)** | The chain is still authenticated. Diagnose from the prompt in the connect window, then `:retry` — it costs no password |
| **The workstation was rebuilt** | Clone the repo, `uv sync`, restore keys, `ac doctor`. There is no other state |
| **The log directory was lost** | Historical trails are gone. Nothing operational breaks; new sessions recreate the directory |
| **Config was corrupted** | Restore from version control. `ac doctor` validates before you connect to anything |

### 6.3 Rollback of a change made *through* the tool

The tool does not roll itself back. Two mechanisms exist:

- A brief may declare a `rollback:` block and `on_failure: rollback` on an
  operation; `ac brief run` executes it when that operation fails.
- Otherwise, rollback is a normal operation you write, run explicitly and gate
  like any other change.

---

## 7. Maintenance

### 7.1 Routine

| Cadence | Task |
|---|---|
| Per change | Validate briefs offline; `ac probe` after any address change |
| Weekly | `ac audit` — look for `incomplete` sessions and blocked commands |
| Monthly | Review `operations.yaml`: is every `host_ids: ['*']` still justified? Is every `requires_permission: false` still read-only? |
| Monthly | Confirm log retention is doing what policy requires; archive what the SIEM does not keep |
| Quarterly | Re-run the hardening checklist in [SECURITY.md](SECURITY.md#10-production-hardening-checklist) |
| On estate change | Update `inventory.yaml`, then `ac routes` and `ac probe` |
| Occasionally | Truncate or rotate `transport.log` and `errors.log` |

### 7.2 Adding a host

1. Add one block under `hops:` or `hosts:` with a `via:` saying how it is reached
   and from where — addresses **as seen from `from:`**, ports explicit.
2. `uv run ac routes <host>` — does it resolve?
3. `uv run ac probe <host> --deep` — does it actually answer?
4. `uv run ac connect <host>` then `ac verify <host> --expect-hostname <NAME>`.

Full walkthrough: [guides/operations-guide.md](guides/operations-guide.md#adding-a-host).

### 7.3 Adding an operation

Edit `config/operations.yaml`, then `ac preview` and `ac run --dry-run` before
anything real. Treat the file as code: it is the only thing standing between an
agent and arbitrary commands. Checklist at the end of
[guides/operations-guide.md](guides/operations-guide.md#checklist-for-a-new-operation).

### 7.4 Retiring a host

Delete or comment out its block. Because connectivity lives inside the block,
its `via:` goes with it — there is no second place to clean up. Then re-run
`ac hosts` to confirm nothing else referenced it (an operation naming a removed
`host_id` is a **hard error** at load time, which is deliberate).

---

## 8. Upgrades

### 8.1 Upgrading the tool

```powershell
git pull
uv sync --extra dev
uv run pytest            # must stay green
uv run ac doctor         # config still parses against the new code
uv run ac hosts          # every route still resolves
```

**Close every live session first.** A running session holds the code it started
with; upgrading underneath it produces confusing half-old behaviour.

Then re-validate any brief you rely on (`ac brief validate`) — validation rules
tighten over time, and it is better to learn that offline.

### 8.2 Upgrading dependencies

`uv.lock` pins everything. To move deliberately:

```powershell
uv lock --upgrade-package paramiko
uv sync --extra dev
uv run pytest
```

Two dependencies deserve a real regression pass rather than a version bump:

- **paramiko** — the multi-hop chain, `PartialAuthentication` (which is *not*
  re-exported at the top level in 5.x), and `direct-tcpip` forwarding.
  `tests/test_e2e.py` exercises all of it against a real in-process SSH server.
- **pypsrp / spnego** — NTLM provider selection and the message-seal wedge
  recovery. **The offline suite cannot cover this**; verify against a real
  Windows host (§8.4).

### 8.3 Upgrading Python

`requires-python = ">=3.12"`. On a new minor version: `uv python install 3.13`,
`uv sync`, `uv run pytest`.

### 8.4 Post-upgrade verification against real hardware

The offline suite cannot test WinRM. After any change to `transport/winrm.py`,
`session.py` or the pypsrp/spnego pins:

```powershell
uv run ac probe <windows-host> --deep
uv run ac connect <windows-host>
uv run ac verify  <windows-host> --expect-hostname <NAME>
uv run ac exec    <windows-host> -- '$env:COMPUTERNAME; (Get-CimInstance Win32_OperatingSystem).Caption'
uv run ac run     <windows-host> windows-health
uv run ac disconnect <windows-host>
```

Note the single quotes: they stop the *local* PowerShell expanding `$env:` before
the command is sent.

### 8.5 Configuration compatibility

Config is loaded with strict validation and reports every problem in one pass, so
an incompatible file fails at `ac doctor` rather than mid-run. The older
declaration styles (`routes:` and per-host `path:`) still load; only combining
them with `via:` is refused.

---

## 9. Capacity and performance

| Dimension | Practical limit | Notes |
|---|---|---|
| Sessions per workstation | One per host id; a handful in practice | Each is a terminal a human authenticated |
| Concurrent clients per session | Thread per request | PSRP `exec` serialises under a lock |
| Campaign fan-out | `max_parallel` (default 8) | Bounded by how many sessions a human opened |
| Step duration | `timeout_s`, default 600 | Installers 1800–5400 |
| Output per command | Clamped to 20 000 chars (head + tail) | Protects an agent's context window |
| Collected diagnostic per source | 6 000 chars | |
| Session socket message | 8 MiB | |

Latency is dominated by the hop chain. `ac verify` reports a round trip over 5 s
as a warning — worth knowing before starting a twenty-step run.

---

## 10. Operational runbook index

| Task | Command |
|---|---|
| Check this machine | `ac doctor` |
| What is declared | `ac hosts`, `ac routes`, `ac routes <host>`, `ac ops` |
| What actually answers | `ac probe <host> --deep` |
| Open / close a session | `ac connect <host>` / `ac disconnect <host>` |
| Prove the right machine | `ac verify <host> --expect-hostname <NAME>` |
| See what would run | `ac preview <host> <op> -p k=v` |
| Do the work | `ac run <host> <op> -p k=v --confirm [--start-at <step>]` |
| Run a whole job | `ac brief run <brief.yaml> --confirm` |
| Fan out | `ac campaign run <campaign.yaml>` |
| Ad hoc | `ac exec <host> -- '<command>'`, `ac logs <host> --path '<glob>'` |
| Move files | `ac upload` / `ac download` |
| Hand a human a desktop or shell | `ac rdp <node>`, `ac shell <node>`, `ac tunnel <node>` |
| Reload the catalogue | `ac reload <host>` |
| What happened | `ac timeline <session-id>`, `ac audit [<session-id>]` |

Every command accepts `--json`. Full flag reference:
[implementation/cli-reference.md](implementation/cli-reference.md).
