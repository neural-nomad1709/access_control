# CLI reference

Every command, every flag, what it connects to, and what it exits with.

Entry point: `ac` (installed by `pyproject.toml`), normally invoked as
`uv run ac <command>`.

**Every command accepts `--json`** except the file-transfer and interactive ones,
which have nothing structured to say. `--json` is what makes the tool drivable by
an agent: it returns the step list, collected logs and hints as data rather than
terminal text to scrape.

---

## Connection requirements at a glance

| Needs nothing | Needs the network | Needs a **live session** |
|---|---|---|
| `version`, `doctor`, `hosts`, `routes`, `ops`, `preview`, `audit`, `timeline`, `brief show`, `brief validate`, `campaign show`, `campaign validate`, `run --dry-run`, `brief run --dry-run`, `campaign run --dry-run` | `probe`, `connect`, and `rdp`/`shell`/`tunnel` when no session exists (they build a temporary one) | `status <host>`, `verify`, `reload`, `disconnect`, `run`, `exec`, `logs`, `upload`, `download`, `brief run`, `campaign run` |

---

## Inspection

### `ac version`

Prints `access-control <version>`.

### `ac doctor`

Checks this workstation is ready. **Touches no network.** Rows: Python version,
each required import, `inventory.yaml` presence, config parse (plus cross-file
warnings), each hop's `key_file` (existence and `.ppk` detection), each host's
resolved route, the available credential prompter, `mstsc`, the `ssh` client, the
audit log and session directories, and any live sessions.

Exits `1` with `N check(s) failed` if anything failed; otherwise prints `Ready.`

### `ac hosts [--json]`

Every configured host: kind, address, automation channel, resolved route, tags,
description. A host whose route does not resolve shows `INVALID: <reason>` rather
than failing the whole command.

### `ac ops [--host <id>] [--json]`

The operation catalogue. Without `--host`, everything; with it, only operations
permitted on that host. Columns: id, what it applies to, parameters (a trailing
`?` marks optional), step ids, and the gate (`destructive` / `approval` / `-`).

`-h` is accepted as the short form of `--host`.

### `ac routes [<host>] [--json]`

Without an argument: every declared edge (source, target, automation endpoint,
interactive endpoint, domain), whether connectivity came from `routes:`/`via:` or
the `path:` shorthand, and the entry points reachable from `local`.

With a host: resolves that one route and prints it verbosely with per-hop
addresses, protocols, pre-established markers and network context, plus the
execution shape (`ssh` / `winrm` / `nested-winrm`).

Exits `1` if the route cannot be resolved.

### `ac probe <host> [--deep] [--json]`

The first command that uses the network. Prompts for the bastion credentials,
then reports per node: which ports answer (`ssh`, `wmi-dcom`, `smb`, `rdp`,
`winrm-http`, `winrm-https`), whether each bastion **permits TCP forwarding**,
and a verdict with advice (`ok` / `change-config` / `bootstrap-needed` /
`unreachable` / `forwarding-blocked` / `reachable-not-authenticated`).

`--deep` additionally authenticates to a Windows jump server and asks *it*
whether it can reach the target — the only honest test of the final nested leg,
because that target is usually invisible from the bastion.

Read-only. The credential store is cleared when it finishes.

---

## Sessions

### `ac connect <host> [--ops a,b] [--allow-exec] [--idle-timeout N] [--max-lifetime N] [--no-shell] [--no-fallback] [--agent-id ID]`

**Run this in your own terminal.** It is the only place a password prompt can
appear. Prompts once per hop, then holds the authenticated path open, serves it
on a loopback socket, and gives you a prompt on the host.

| Flag | Default | Effect |
|---|---|---|
| `--ops a,b` | all permitted for the host | Restrict this session to these operations. The session then refuses anything else even if `operations.yaml` is edited underneath it, and refuses ad-hoc commands (`ac exec`) too |
| `--allow-exec` | off | With `--ops`, still permit `ac exec`. No effect without `--ops` |
| `--idle-timeout N` | `1800` | Seconds of inactivity before the session closes and credentials are wiped. `0` = never |
| `--max-lifetime N` | `0` | Absolute seconds before the session closes regardless of activity, measured from connect. Bounds a continuously driven session the idle timer alone would keep open. `0` = no ceiling |
| `--no-shell` | off | Hold the session open with no prompt — for a service wrapper, or a log you want kept clean. Close with Ctrl-C |
| `--no-fallback` | off | Fail outright if the target leg fails, instead of holding the session at the last hop that authenticated |
| `--agent-id ID` | generated per run | Agent id recorded on every audit line for this session, e.g. a per-window name (`AGT-web01`) or a batch tag. Overrides `AC_AGENT_ID`. Either one marks the session as agent-driven: `--confirm` then carries no weight and gated work waits for `:approve` |

Refuses to start if a session for that host already exists. Warns if this is not
an interactive terminal.

**Fallback behaviour:** if the bastion chain stands up but the target leg fails,
the session is *held at the last authenticated hop* rather than thrown away — the
passwords are already typed, and the hop is the machine that was supposed to
reach the target. While degraded, catalogue operations and `ac exec` are refused;
`:retry` at the prompt re-attempts the final leg at no credential cost.

Exit `130` on Ctrl-C during connect.

#### The operator prompt

The window becomes a REPL on the machine named in the prompt:

```
appuser@10.0.0.29 [app-stg01-bastion] $
operator@bastion-staging.example.net [bastion-staging · FALLBACK] $
```

| Command | Effect |
|---|---|
| `:help`, `?` | The prompt's own help |
| `:status` | Session id, host, current node, route, connected, idle, expiry, audit file |
| `:where` | Which machine this is, its description, and whether it is a fallback |
| `:route` | The full hop chain verbatim from the inventory |
| `:retry` | Re-attempt the target leg (only meaningful when degraded) |
| `:timeout <secs>` | Per-command timeout (default 300) |
| `:approve` | List the approvals an agent is waiting on, with the exact commands each would run |
| `:approve <id>` | Approve one. It authorizes one run of exactly those commands |
| `:deny <id>` | Refuse one |
| `:exit`, `:quit` | Close the session and wipe credentials |

**Approving an agent's gated work.** When an agent asks for a gated operation or
a `CONFIRM`-class command, nothing runs. The request is held, this window prints
`approval requested: apr-…` with the commands, and the agent is told to re-run
once you have answered. A request you ignore lapses after 15 minutes and counts
as a denial. A request is the agent's when the session was opened with
`--agent-id` (or `AC_AGENT_ID`), or when the `ac run` / `ac exec` /
`ac brief run` / `ac campaign run` command was itself started inside an agent
harness such as Claude Code. Your own `ac run --confirm` from a plain terminal
is not held. If `ac connect` itself was started inside an agent harness, its
prompt cannot approve anything: open the session from your own terminal.

Anything else runs on that machine through the same audited channel, with the
same deny-list — `CONFIRM`-class commands are allowed (a human typed them), but
`BLOCKED` still holds. `cd` is remembered between commands on POSIX hosts;
nothing else is, because each command opens its own channel. Ctrl-C abandons the
current line; Ctrl-D closes the session.

### `ac status [<host>] [--json]`

Without a host: every live session (host, session id, pid, agent id). With one:
the full report — route, connected state, steps ok/failed, elapsed, expiry, audit
file, summary file, and in `--json` also tunnels, authenticated nodes and
degraded state.

### `ac reload <host> [--json]`

Re-reads `operations.yaml` into the live session without reconnecting (which
would cost a password at every hop). Reports what was added and removed, plus any
cross-file warnings.

**Refused if the host's route changed** in `inventory.yaml` — the live connection
would no longer match the config, and the honest answer is to reconnect. The
running session is unaffected by the refusal.

### `ac disconnect <host> [--json]`

Prints the final status **before** tearing anything down, then closes the session
and wipes credentials. The audit trail stays on disk.

---

## Verification

### `ac verify <host> [--expect-hostname NAME] [--json]`

Runs the preflight checks against a live session:

| Check | Proves |
|---|---|
| `session.live` | The session is open and has not idled out |
| `chain.intact` | Every SSH hop's transport is still up |
| `target.responds` | The far end answers a trivial command (a round trip over 5 s is a warning) |
| `target.identity` | **You are on the machine you think you are** |

`--expect-hostname` is matched case-insensitively, and a short name matches its
own FQDN. Without it the check passes with a warning, because there is nothing to
compare against.

Exits `2` if any fatal check failed.

**Run this before any real work, and again after anything that might have
disturbed the path.** Every hop past the first arrives over a local port forward,
and a port number carries no identity.

---

## Work

### `ac preview <host> <operation> [-p name=value]... [--json]`

Renders every command with placeholders filled in and reports each step's policy
verdict. **Connects to nothing** — it builds an offline session purely to resolve
the route and the catalogue.

This is what you show an operator when asking for approval: approving
`Install {{package}}` is not informed consent; approving the rendered command is.
Output is printed with markup disabled so `[math]::Round` survives verbatim.

### `ac run <host> <operation> [-p name=value]... [--confirm] [--dry-run] [--only ids] [--start-at id] [--summary] [--json]`

Runs an operation on a host.

| Flag | Effect |
|---|---|
| `-p`, `--param name=value` | Repeatable. Values are strings |
| `--confirm` | Approves a gated (or destructive) operation. Without it, a gated operation is refused **and the refusal quotes the fully rendered commands**. From an agent it carries no weight: the operation is held for `:approve` at the operator prompt instead |
| `--dry-run` | Renders and reports policy, executes nothing. **Works with no live session** |
| `--only a,b` | Run only these step ids |
| `--start-at id` | Resume from this step onward — use after fixing a failure rather than re-running from the top |
| `--summary` | Print the full end-to-end Markdown report instead of the step log |
| `--json` | The whole `OperationOutcome`, including `summary`, `summary_file`, per-step `collected_logs`, `hint` and `next_action` |

Exits `2` if the operation did not succeed, so a shell or CI job can check the
return code rather than parsing output.

### `ac exec <host> -- <command…> [--shell s] [--confirm] [--timeout N] [--json]`

One ad-hoc command on a host. Note the `--` before the command.

| Flag | Default | Effect |
|---|---|---|
| `--shell` | the host's default (`powershell` on Windows, `bash` otherwise) | `powershell` \| `cmd` \| `bash` |
| `--confirm` | off | Approves a `CONFIRM`-class command |
| `--timeout` | `300` | Seconds |

Prints exit code, duration, node and channel, then stdout, then PowerShell error /
warning / verbose streams separately.

> On Windows, wrap the remote script in **single quotes** so your local PowerShell
> does not expand `$env:` before the command is sent.

A session opened with `ac connect --ops` refuses `ac exec` (exit 1, audited as
`COMMAND_BLOCKED`) unless it was also opened with `--allow-exec`. The deny-list
applies either way. Commands typed at the `ac connect` prompt are the
operator's own and are not affected.

### `ac logs <host> --path <file-or-glob> [--tail N] [--json]`

Tails a remote log. A glob resolves to the **most recently written** match, which
is how you find an installer log with a generated name. `--tail` defaults to 200.

Works in a session restricted with `--ops`. The path is passed to the remote
shell as one literal argument (glob characters still expand), so it cannot carry
a second command.

### `ac upload <host> <local> <remote>`

Copies a local file to the host. SFTP on SSH channels, WinRM `copy` on Windows
(slow — WinRM base64-encodes the payload; prefer a server-local share). **Not
supported through a Windows jump server** on a nested route.

### `ac download <host> <remote> <local>`

The reverse. Same nested-route limitation.

---

## Task briefs

### `ac brief show <path> [--json]`

Renders a brief for a human to read and approve: header, operations in order with
parameters and failure modes, success criteria, `must_not`, rules, rollback.

### `ac brief validate <path> [--json]`

Validates against the inventory and catalogue. **Connects to nothing.** Errors
(the brief will not run): unknown host, unroutable host, unknown operation,
operation not permitted on that host, undeclared or missing parameter, unknown
`start_at`/`only_steps`, `on_failure: rollback` with no rollback block, a
rebooting operation under `reboot_allowed: false`, a misspelled rule. Warnings: no
`expect_hostname`, no `success_criteria`, no `change_ref`, a destructive operation
with `confirm_destructive: false`.

Exits `2` on failure (and with `--json` emits `{"ok": false, "error": …}`).

### `ac brief run <path> [--confirm] [--dry-run] [--skip-preflight] [--json]`

Executes a brief against a live session for its host: preflight, then each
operation in order honouring `on_failure` (`stop` / `continue` / `rollback`),
then the success-criteria checklist.

| Flag | Effect |
|---|---|
| `--confirm` | Approves the gated operations this brief contains |
| `--dry-run` | Renders everything and connects to nothing |
| `--skip-preflight` | Not recommended — preflight is the safety net |

Exits `2` if any operation failed. A failed preflight stops the run with nothing
executed.

---

## Campaigns

### `ac campaign show <path> [--json]`

Renders the campaign: targets and the brief each runs.

### `ac campaign validate <path> [--json]`

Loads and validates **every** target's brief offline, and reports per host whether
a live session exists. Connects to nothing.

### `ac campaign run <path> [--dry-run] [--confirm] [--parallel N] [--json]`

Dispatches each target's brief to that host's **already-live** session,
concurrently. Hosts without a session are reported and **skipped, not connected
to** — campaigns handle no credentials.

`--parallel` overrides the campaign's `max_parallel` (default 8). `--confirm`
pre-approves gated operations fleet-wide. Progress is printed per host
(`▶ start`, `✓ done`, `• skipped`). Exits `2` if any target did not succeed.

---

## Interactive handoff

### `ac rdp <node> [--stage-credentials] [--full-screen]`

Forwards the node's RDP port through the chain and launches `mstsc`. Works for a
hop or a host. Refused if the node is not configured for RDP.

If a session is live it borrows that session's tunnel and pre-fills the username
from it; otherwise it opens a temporary session just to carry the forward.

The destination is the address the route declares for RDP (the leg's
`interactive:` endpoint), not the node's own `hostname:`. If that endpoint is
`preestablished: true`, `mstsc` is pointed straight at it: no tunnel is built and
no hop is authenticated. If only another protocol was forwarded (say WinRM), the
command is refused, because another port on `localhost` is your own machine.

Every launch is recorded as `RDP_LAUNCH`: in the live session's trail, or in a
trail of its own when there is no session.

`--stage-credentials` pre-fills the password via `cmdkey` instead of letting
`mstsc` prompt. **Off by default** — letting Windows prompt keeps the password out
of any process list. The staged credential and the generated `.rdp` file are
always removed afterwards, including on interruption.

Also the bootstrap path for a host with WinRM disabled: log in once and run
`Enable-PSRemoting -Force`.

### `ac shell <node>`

An interactive SSH shell through the chain, using the system `ssh` client (it
handles raw mode, resizing and Ctrl-C correctly on Windows). Host-key checking is
disabled for the *loopback endpoint only* — the forward already terminates on a
bastion whose key was verified.

The destination is the address the route declares for SSH. If it is
`preestablished: true`, `ssh` is pointed straight at that forward and nothing is
tunnelled.

### `ac tunnel <node> [--port N] [--remote-port N]`

Holds a port forward open through the same authenticated chain, for any client:
`mstsc`, mRemoteNG, a database tool, a browser. Prints the local endpoint and the
exact `mstsc` / `ssh` commands to use it. Ctrl-C closes it.

`--port 0` (default) picks a free port; a requested port that is unavailable is
an error, never a silent substitute. `--remote-port` overrides the node's
declared port.

Refused for a node declared `preestablished: true` — there is nothing for this
command to build.

---

## Agent access

### `ac mcp <host>`

Serves the live session for `<host>` as an MCP server on stdio. Needs a session
already open with `ac connect`; it attaches to it and opens nothing itself.

The tools are a 1:1 wrapper of the agent-facing daemon methods: `ac_status`,
`ac_preflight`, `ac_operations`, `ac_preview`, `ac_run_operation`,
`ac_run_command`, `ac_fetch_log`. Tunnels, credentials and session lifecycle are
not exposed, and `confirmed` is stripped from every call, so an agent cannot
self-approve a gated operation through it. Details:
[session-protocol.md](session-protocol.md#the-mcp-face).

It is designed to run behind AgentLighthouse's MCP proxy, which is part of the
integrated mode: [../integration/mcp-proxy-config.md](../integration/mcp-proxy-config.md).

---

## Audit

### `ac audit [<session-id>] [--limit N] [--json]`

Without an argument: recent sessions (default 20) with start time, host, agent,
status and step counts. A `status` of `incomplete` means the session never wrote
a close record — the terminal was killed or the process died.

With a session id: every record in that session's trail.

### `ac timeline <session-id> [--json]`

The execution trace: each action in order with source → target, detail and
duration. The fastest first look after a failure.

```
12:49:07  SSH_CONNECT      local -> bastion1  bastion1.example.net:2222 (1.2s)
12:49:09  SSH_CONNECT      bastion1 -> app01  10.0.0.36:22 (0.4s)
12:49:12  COMMAND_EXECUTE  local -> app01  df -h (0.3s)
12:49:15  SESSION_END      local -> app01
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | An `AccessControlError`, a failed `doctor`, or an unexpected exception (traceback appended to `<log dir>/errors.log`) |
| `2` | The work itself failed: a failed operation, brief, campaign, or preflight/verify |
| `130` | Cancelled with Ctrl-C |

---

## Environment variables

See [../CONFIGURATION.md](../CONFIGURATION.md#2-environment-variables) for the
full table. The ones that change CLI behaviour most often:

| Variable | Effect |
|---|---|
| `AC_AGENT_ID` | Pins the agent id on every audit record |
| `AC_CONFIG_DIR` | Where `inventory.yaml` / `operations.yaml` are read from |
| `AC_LOG_DIR` | Overrides the audit log directory |
| `AC_PROMPTER` | `terminal` \| `windows` \| `none` |
| `AC_HOST_KEY_POLICY` | `accept-new` (default) or `strict` |
