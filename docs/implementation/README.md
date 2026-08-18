# Implementation guide

Module contracts, the conventions to follow when extending this, and the
non-obvious mechanics (exit codes, quoting, secret passing) that a change is
likely to break.

| Also here | |
|---|---|
| [cli-reference.md](cli-reference.md) | Every command and flag, exit codes |
| [audit-events.md](audit-events.md) | Every audit record and its fields |
| [session-protocol.md](session-protocol.md) | The loopback wire protocol |

Architecture and flows: [../ARCHITECTURE.md](../ARCHITECTURE.md).

---

## Layout

```
src/access_control/
  __init__.py       version, APP_NAME
  paths.py          Where things live. Audit logs go outside the repo, always.
  redact.py         Secret scrubbing. Everything user-visible passes through it.
  errors.py         Exception hierarchy; every message is self-scrubbing.
  template.py       Strict {{name}} rendering -- unresolved raises, never blanks.
  context.py        NetworkContext, AgentIdentity, LoggingConfig, domain qualifying.
  routegraph.py     Declared edges + resolution. No I/O, no discovery, fail-fast.
  config.py         inventory.yaml + operations.yaml -> validated dataclasses.
  route.py          A resolved edge chain -> an executable plan. Pure, no I/O.
  credentials.py    Prompting. Never stores. Terminal or Windows dialog.
  safety.py         Command deny-list. BLOCKED / CONFIRM / ALLOWED.
  audit.py          Append-only JSONL trail, canonical actions, timeline, summary.
  logging_setup.py  Library logging -> a file; unexpected tracebacks -> errors.log.
  probe.py          Live capability detection per hop.
  preflight.py      Liveness, chain, round trip, IDENTITY, and brief-declared checks.
  session.py        One authenticated path: hops, tunnels, channels. Owns teardown.
  engine.py         Runs steps, judges results, collects diagnostics on failure.
  brief.py          Task-brief parsing and offline validation.
  campaign.py       Fan-out of one brief across many hosts' live sessions.
  daemon.py         Holds a session in a process; loopback JSON protocol.
  operator_shell.py The REPL inside the `ac connect` window.
  cli.py            typer front end.
  transport/
    base.py         ExecResult + the Channel protocol.
    pshell.py       PowerShell wrapping, exit sentinel, -EncodedCommand.
    ssh.py          Paramiko, chained hop to hop.
    tunnel.py       Local port forward anchored at an SSH hop, + forwarding probes.
    winrm.py        PSRP over the tunnel + the nested Windows-to-Windows leg.
    interactive.py  mstsc / ssh handoff to a human.
```

Dependencies run one way:

```
cli → daemon → engine → session → transport → route → config → routegraph
                                                             → context / redact
```

Nothing in `transport` imports `engine`, and `routegraph` imports nothing but
`context` and `errors` — which is why route resolution is testable with no
fixtures at all.

---

## Routing: two modules, two questions

`routegraph.py` answers **"is there a declared path, and what is it?"** It holds
only edges and contexts, and resolves by breadth-first search over declarations.
It never opens a socket.

`route.py` answers **"how do we traverse it?"** It turns a resolved edge chain
into `Leg` objects pairing each node with the endpoint declared for reaching it,
and classifies the chain into `ssh` / `winrm` / `nested-winrm`.

`classify_chain` deliberately lives in `routegraph` rather than `route`, because
it works on protocols alone. That lets `config.py` call it at **load** time — so
an untraversable topology is a config error, not a surprise three passwords into
a run — without `config` having to import `route` (which would be circular).

`config.load_inventory` also *resolves every host* at load time, so a missing or
ambiguous route surfaces when the file is read.

---

## Layer contracts

### `transport.*` — one machine, one command

A channel knows how to reach one kind of machine and run one command on it, and
nothing about operations, sessions, or policy. Every channel implements:

```python
exec(command, *, shell="powershell", timeout_s=600) -> ExecResult
upload(local_path, remote_path) -> None
fetch(remote_path, local_path) -> None
close() -> None
```

`ExecResult` scrubs itself on construction and clamps output to 20 000
characters, keeping the head (⅔) and tail (⅓) — a runaway `Get-WinEvent` must not
blow up an agent's context, and the middle is the part least likely to carry the
diagnosis.

Streams stay separate. `ps_errors`, `ps_warnings`, `ps_verbose` and
`ps_information` are distinct fields, because an installer that writes its real
diagnosis to the error stream while exiting 0 is common, and `*>&1` would bury it.

### `session.Session` — one authenticated path

Owns, in order: SSH hops → tunnel → PSRP channel → nested channel. Tears them
down in reverse and wipes credentials. Everything it exposes calls
`require_active()` first, which produces an actionable message when the session
has expired or a hop has dropped.

Two behaviours worth knowing before changing it:

- **Fallback.** If the target leg fails but the chain stands, `_degrade_to_hop`
  holds the session at the last authenticated node (the *jump server* if PSRP got
  that far, otherwise the last SSH hop). `exec` then refuses unless the caller
  passes `allow_degraded=True`, and `operations()` returns an empty list.
  `retry_target()` re-attempts the final leg without re-authenticating anything
  below it.
- **Direct WinRM.** When there is no SSH hop and the endpoint is not
  pre-established, `_connect_winrm` connects straight to the declared address.
  That only happens for an explicit `via: {from: local}` edge, so "declared, never
  discovered" still holds — and it emits its own `winrm.direct` audit event.

### `engine.Engine` — steps and judgement

Renders, polices, runs, judges, collects. Returns `OperationOutcome` /
`StepOutcome`, and writes the shareable Markdown report next to the audit trail.
**Never remediates** — see [../ARCHITECTURE.md](../ARCHITECTURE.md#62-run--executing-an-operation).

`_write_report` never raises: losing the report must not turn a recoverable
failure into an exception.

### `preflight` — checks, in a deliberate order

`session.live` → `chain.intact` → `target.responds` → `target.identity`, each
fatal-stopping, *then* the brief's declared checks. There is no point measuring
free space on a machine that turns out to be the wrong one.

A custom check must classify as `ALLOWED` by the deny-list: preflight verifies
state, it does not create it.

### `daemon` — the process boundary

`SessionServer` serves one session over loopback; `SessionClient` calls it. The
wire protocol is one line of JSON in, one line out. Adding a method means adding
`do_<name>(self, **params)` — the dispatcher finds it by name. See
[session-protocol.md](session-protocol.md).

### `campaign` — fan-out

`plan_campaign` validates every target's brief offline and retargets one brief
template to many hosts. `run_campaign` dispatches through a bounded
`ThreadPoolExecutor`; `execute_brief_on_client` **prints nothing**, which is what
makes it thread-safe. `attach` and `execute` are injectable for testing.

A host may appear once per campaign — one host has one session.

---

## Exit codes

PowerShell has no single notion of "the exit code". A native tool sets
`$LASTEXITCODE`; a cmdlet throws; `powershell.exe -EncodedCommand` exits 0 unless
told otherwise; and PSRP has no process exit code at all.

Every PowerShell script is therefore wrapped by `pshell.wrap_script`:

```powershell
$ProgressPreference = 'SilentlyContinue'
$global:LASTEXITCODE = 0
$__ac_exit = 0
try {
    & {
    <your script>
    } | Out-String -Width 512          # only when out_string=True (PSRP)
    if ($null -ne $LASTEXITCODE) { $__ac_exit = $LASTEXITCODE } else { $__ac_exit = 0 }
} catch {
    Write-Error ($_ | Out-String)
    $__ac_exit = 1
}
Write-Output ('__AC_EXIT__:' + $__ac_exit)
```

Both the SSH and WinRM channels parse that sentinel back out with
`pshell.parse_exit`. On the nested leg two sentinels come back — the jump
server's and the target's — and **the last one wins**, so the target's code is
what the agent sees.

`$ErrorActionPreference` is deliberately left at its default. Forcing `Stop`
would abort scripts that legitimately produce non-terminating errors, such as
`Get-Item` on a path that may not exist while probing.

For PSRP the wrapper also pipes the success stream through `Out-String`; without
it a `PSCustomObject` arrives in Python as a type name rather than a readable
table. It touches only the success pipeline, so the error stream stays separate.

If the sentinel never appears (the pipeline was stopped or died), the WinRM
channel falls back to `None` on timeout, `1` if anything wrote to the error
stream, else `0`.

---

## Quoting

For SSH, the wrapped script is sent as UTF-16LE base64 via `-EncodedCommand`.
Nothing in it can be re-quoted or mangled by an intervening shell. Use
`pshell.quote_single` when interpolating a value into a PowerShell single-quoted
literal, and `_sh_quote` (in `ssh.py`) for a POSIX shell.

A `shell: cmd` step on a Windows channel is routed as
`& cmd.exe /c '<command>'` so there is one code path and one exit-code
convention.

---

## Passing secrets to a remote script

**Never interpolate a credential into script text.** PowerShell script-block
logging (event 4104) records the script a jump server executes, so an
interpolated password lands in that server's event log in clear text.

Bind it as a parameter instead. `winrm.nested_invoke_script` takes `$AcPassword`
as a mandatory parameter, builds the `PSCredential` remotely, and removes the
variables in a `finally` block. The value travels as a PSRP argument object, not
as part of the logged script body.

---

## WinRM transport wedge recovery

Pure-Python NTLM can desync its message-seal counters, after which every sealed
request comes back as an empty `Bad HTTP response … Code: 400`. The counters live
in the auth context held by the pypsrp client's WSMan transport, so reopening the
runspace pool is not enough — the whole client has to be rebuilt.

`WinRMChannel` handles this transparently:

- `_looks_wedged(exc)` matches the wedge signatures (`bad http response`,
  `code: 400`, `10054`, connection reset/aborted/forcibly closed).
- `_reopen()` discards the pool, rebuilds the client from `_client_kwargs`
  (reusing the stored credential, so no re-prompt) and opens a fresh pool.
- `_invoke(..., attempt=1)` re-runs the **same** script exactly once. Safe,
  because a wedge rejects the request at the HTTP/auth layer *before* the shell
  executes it.
- `WinRMChannel.reopens` counts recoveries.

If you change the retry logic, keep the "rejected before execution" property —
retrying a command that may have partially run would be a correctness bug, not a
resilience feature.

---

## Adding things

### A new operation

Edit `config/operations.yaml`. No code. See
[../guides/operations-guide.md](../guides/operations-guide.md).

### A new host or hop

Edit `config/inventory.yaml`: add one block for the machine, including a `via:`
declaring how it is reached and from where. Confirm with `ac routes <host>` (does
it resolve?) and `ac probe <host>` (does that port actually answer?).

### A new protocol on an edge

1. Add it to `routegraph.PROTOCOLS`, and to `AUTOMATION_PROTOCOLS` only if it can
   genuinely return an exit code.
2. Add its default to `DEFAULT_PORTS` — used only in the error message that
   explains why the port is required.
3. Add it to `config._PORT_FIELD_FOR` if a `via:` endpoint of that protocol should
   populate one of the node's port fields.
4. Handle it in `classify_chain` and in `Session._open_target_channel`.

### A new audit action

Add the name to `audit.ACTIONS` and call `audit.action(...)` with `source`,
`target` and `result`. Anything that reaches an operator's machines should be an
action, not a bare `emit` — actions are what `ac timeline` and SIEM filters see.
Then document it in [audit-events.md](audit-events.md).

### A new execution channel

1. Implement the `Channel` protocol in `transport/`.
2. Add a constant and a shape to `route.py`/`routegraph.py`, with a specific
   error for the combinations it cannot handle.
3. Wire it into `Session._open_target_channel`.
4. Add the port to `probe.PORTS` and `probe.CHANNEL_REQUIREMENTS`.
5. Unit-test the route shape offline; it needs no network.

### A new deny-list rule

Add a `Rule` to `safety.RULES`, BLOCKED entries first (the list is ordered and
first match wins). Two things to get right:

- **Anchor command-name patterns.** A bare `\breboot\b` matches the word in a
  comment. Use command position: `(?:^|[\n;&|]\s*|\bthen\s+|\bdo\s+)`.
- **Watch `\b` against punctuation.** `\b/x\b` does *not* match ` /x ` — the
  boundary before `/` fails after a space. Use `[/-]x\b`.

Both of these were live bugs caught by the test suite; there are regression tests
for each in `tests/test_security.py`.

### A new preflight check

Add a `check_*(session, …) -> CheckResult` to `preflight.py` and call it from
`run_preflight`, after the four connection checks. Give it a `remedy` — a failing
check that does not say what to do about it is half a feature. Then document the
`preflight:` key in [../CONFIGURATION.md](../CONFIGURATION.md#51-preflight) and
[../guides/instructions-guide.md](../guides/instructions-guide.md).

### A new CLI command

Add it to `cli.py` with a `--json` option, use `_raw`/`_raw_panel` for anything
remote, and route failures through `_fail` (exit 1) or `typer.Exit(2)` (the work
itself failed). Document it in [cli-reference.md](cli-reference.md).

---

## Conventions

- **Error messages tell the operator what to do next.** Not "authentication
  failed" but "authentication failed. Nothing was stored; you will be prompted
  again on retry." Every `ConnectionFailed` in `transport/ssh.py` follows this.
- **Teardown never raises.** `close()`, `cleanup()`, and `finally` blocks swallow
  their own errors so they cannot mask the real one.
- **Validate at load time.** A misconfigured inventory must fail before a session
  is opened, not halfway through a patch run. `config.py` reports every problem
  it can find in one pass.
- **Strict templating.** `Remove-Item {{path}}` silently becoming `Remove-Item`
  is how you delete the wrong thing. `template.render` raises instead.
- **Anything remote is printed with `markup=False`.** Rich treats `[math]::Round`
  as a style tag and silently eats it. The operator approves based on that text,
  so it must be verbatim. Use `cli._raw` / `cli._raw_panel`.
- **Everything that leaves the process is redacted.** If you add a new output
  path, make sure it goes through `redact` — or better, through a type that
  already does (`ExecResult`, `AuditLog.emit`, `RedactingError`).
- **New public behaviour needs a test that asserts what the operator depends on**,
  not what the method returns. See [../guides/testing.md](../guides/testing.md).
