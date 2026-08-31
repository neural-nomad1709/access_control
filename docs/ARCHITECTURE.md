# Architecture

How `access-control` is put together: components, data flows, the authentication
and authorization paths, the request lifecycle, and where the trust boundaries
sit.

> Module-level contracts and extension points are in
> [implementation/README.md](implementation/README.md). Rationale for individual
> features, and how each compares to the alternatives, is in
> [guides/features.md](guides/features.md).

---

## 1. What the system is

A single-user, client-side CLI (`ac`) that:

1. resolves a **declared** path from the operator's machine to a target server
   through a chain of bastion and jump hosts,
2. authenticates each hop with a credential typed by a human at that moment,
3. holds that authenticated path open in one process,
4. runs **catalogued** operations over it, judging each step against a declared
   expectation and collecting diagnostics when one fails,
5. writes an append-only, secret-scrubbed audit trail of everything.

There is no server component, no daemon installed on targets, and no agent
software deployed anywhere. Everything runs as the operator's own user on the
operator's own machine.

---

## 2. Component map

```
                       operator's workstation
 ┌───────────────────────────────────────────────────────────────────────┐
 │                                                                       │
 │  ┌─────────────────────────┐        ┌──────────────────────────────┐  │
 │  │  ac connect  (terminal) │        │  ac run / exec / verify /    │  │
 │  │  ───────────────────────│        │  brief / campaign / logs ... │  │
 │  │  credentials.Prompter   │        │  (thin clients, no secrets)  │  │
 │  │  operator_shell (REPL)  │        └───────────────┬──────────────┘  │
 │  │  daemon.SessionServer   │◄───127.0.0.1 + token───┘                 │
 │  └───────────┬─────────────┘        daemon.SessionClient              │
 │              │                                                        │
 │        session.Session ──── engine.Engine ──── safety (deny-list)     │
 │              │                    │                                   │
 │              │                    └── audit.AuditLog ──► *.jsonl/.md  │
 │              │                                                        │
 │   route.Route (plan)  ◄── routegraph.RouteGraph ◄── config (YAML)     │
 │              │                                                        │
 │   transport: ssh.SSHHop → tunnel.LocalTunnel → winrm.WinRMChannel     │
 │                                             → winrm.NestedWinRM       │
 │                                             → interactive (mstsc/ssh) │
 └──────────────┬────────────────────────────────────────────────────────┘
                │ SSH (22 / 2222 …)
        ┌───────▼────────┐
        │  Bastion (SSH) │  environment: QA/CVT/PROD, zone, owner
        └───────┬────────┘
                │ direct-tcpip channel  →  loopback listener on the workstation
        ┌───────▼────────────┐
        │ Jump server (Win)  │  PSRP over the forwarded 5985
        └───────┬────────────┘
                │ Invoke-Command with an explicit PSCredential
        ┌───────▼────────┐
        │ Target server  │  Windows (WinRM) or Unix/Linux/AIX (SSH)
        └────────────────┘
```

### Modules, one line each

| Module | Responsibility |
|---|---|
| `cli.py` | Typer front end. Every command accepts `--json`. |
| `daemon.py` | Holds one `Session` in a process; loopback JSON-line protocol; descriptor files. |
| `operator_shell.py` | The REPL inside the `ac connect` window (`:help`, `:where`, `:retry`). |
| `session.py` | One authenticated path: hops → tunnels → channels. Owns teardown and credential wiping. |
| `engine.py` | Renders a step, applies policy, runs it, judges the result, collects diagnostics, writes the report. |
| `safety.py` | Command classification: `BLOCKED` / `CONFIRM` / `ALLOWED`. |
| `preflight.py` | Liveness, chain, round-trip and **identity** checks, plus brief-declared checks. |
| `probe.py` | Live capability detection per hop (which ports answer, is forwarding permitted). |
| `brief.py` | Task-brief parsing and offline validation. |
| `campaign.py` | Fan-out of one brief across many hosts' live sessions. |
| `config.py` | `inventory.yaml` + `operations.yaml` → validated dataclasses. |
| `routegraph.py` | Declared edges and route resolution (BFS). No I/O. |
| `route.py` | A resolved edge chain → an executable plan (`ssh` / `winrm` / `nested-winrm`). |
| `context.py` | `NetworkContext`, `AgentIdentity`, `LoggingConfig`, domain qualification. |
| `credentials.py` | Prompting (terminal / Windows dialog) and the in-memory store. |
| `audit.py` | Append-only JSONL trail, canonical actions, timeline, Markdown summary. |
| `redact.py` | Secret registry and scrubbing applied to everything that leaves the process. |
| `logging_setup.py` | Routes library logging to a file; records unexpected tracebacks. |
| `paths.py` | Where config, logs and session state live (always outside the repo). |
| `template.py` | Strict `{{name}}` rendering — an unresolved placeholder raises. |
| `errors.py` | Exception hierarchy; every message self-scrubs. |
| `transport/*` | One machine, one command: SSH, tunnel, WinRM/PSRP, nested WinRM, interactive. |

Dependencies run one way:

```
cli → daemon → engine → session → transport → route → config → routegraph
                                                             → context
                                                             → redact
```

Nothing in `transport` imports `engine`; `routegraph` imports only `context` and
`errors`, which is why route resolution is testable with no fixtures at all.

---

## 3. The three configuration inputs

| File | Question it answers | Lifetime | Contains secrets |
|---|---|---|---|
| `config/inventory.yaml` | *Where are the machines and who do I log in as?* | Per estate change | **No** |
| `config/operations.yaml` | *What may ever be run, and on which hosts?* | Rarely; reviewed like code | **No** |
| A task brief (`config/briefs/*.yaml`) | *What should happen on this host, this time?* | Per change / ticket | **No** |
| A campaign (`config/campaigns/*.yaml`) | *Which hosts run which brief in this fan-out?* | Per sweep | **No** |

All four are plain YAML, hold no credentials, and are meant to be committed and
shared. Every password is typed at connect time. Full field reference:
[CONFIGURATION.md](CONFIGURATION.md).

---

## 4. Connectivity is declared, never discovered

`routegraph.py` holds a directed graph built **only** from declared edges.
Resolution is a breadth-first search over those declarations. It never opens a
socket to find out, never guesses, and never falls back to a direct connection
when the hierarchy is missing.

```
local ──► bastion1 ──► JumpServer01 ──► win-app01
```

Each edge carries how the target is addressed **from that source**, because the
same machine is reached differently depending on where you are standing: a jump
server might be `10.20.4.11:5985` from the bastion and `localhost:45985` on the
operator's laptop where a tunnel already terminates.

A target with no inbound edge produces, before any socket is opened:

```
ERROR: No route defined between requested target and available bastion.
  requested target : linux-app01
  reason           : no declared edge reaches it
  known nodes      : bastion1, JumpServer01
Routes are never discovered; a direct connection will not be attempted.
```

### Declaration styles

| Style | Shape | Status |
|---|---|---|
| `via:` on each node | The leg lives inside the block of the machine it reaches | **Preferred** |
| Top-level `routes:` list | `{source, target, hostname, port, protocol}` edges | Accepted |
| Per-host `path: [bastion1, jump1]` | Uses each node's own `hostname`/`port` | Accepted, simplest linear case |

All three compile to the same edge set and one resolution engine. Combining
`via:` with a top-level `routes:` block in one file is **refused at load time** —
connectivity declared in two places is exactly the drift `via:` exists to prevent.

### Rules enforced during resolution

| Rule | Effect |
|---|---|
| Ports are mandatory on every edge | The error names what the default would have been, rather than using it |
| Ambiguity is refused | Two declared paths of equal length raise, rather than one being picked |
| `context.environment` is a hard boundary | A route may not cross it (QA bastion ⇏ PROD target) |
| RDP can never be an `automation` endpoint | It carries pixels, not exit codes; rejected at load time |
| An intermediate hop must be automatable | An interactive-only jump server cannot launch the next leg |
| At most one Windows jump server | Nesting `Invoke-Command` deeper means passing a credential through an intermediate script |
| SSH may not follow WinRM in a chain | Chaining back to SSH from a Windows jump is unsupported |
| An empty `path:` needs `vars.allow_direct: true` | A direct connection bypasses every bastion, so it must be said out loud |

Every one of these is raised when the config is **read**, not when you connect.
`config.load_inventory` resolves every host at load time for this reason.

---

## 5. Route shapes

`route.py` classifies a resolved edge chain into exactly one executable shape.

| Shape | Path | Mechanism |
|---|---|---|
| `ssh` | SSH legs → SSH target | Paramiko `direct-tcpip`, hop to hop (OpenSSH `ProxyJump` equivalent) |
| `winrm` | SSH legs → Windows target | Local forward anchored at the last SSH hop; PSRP over it |
| `nested-winrm` | SSH legs → Windows jump → Windows target | PSRP to the jump, then `Invoke-Command` onward |

A fourth case exists as a special form of `winrm`: **direct WinRM**, where the
route's only edge is `from: local` with the target's real address (VPN or same
segment). There is no SSH hop to anchor a tunnel at, so the channel connects
straight to the declared endpoint. This is still *declared*, not discovered — it
only happens for an explicit `via: {from: local}` edge — and it emits its own
`winrm.direct` audit event because it bypasses every bastion.

---

## 6. Data flows

### 6.1 Connect — building the path

```
ac connect win-app01
 │
 ├─ config.load_all()            inventory + catalog + cross-validation
 ├─ route.plan_route()           resolve, classify, validate (no I/O yet)
 ├─ audit.open_session()         SESSION_START record on disk
 │
 ├─ STAGE 1: SSH chain  (transport/ssh.connect_chain)
 │    for each SSH leg:
 │      ├─ TCP connect (through the previous hop's direct-tcpip channel)
 │      ├─ verify_host_key()     known / new / MISMATCH→fatal
 │      ├─ authenticate: agent → publickey → password → keyboard-interactive
 │      │     (credentials.Prompter asks the human, once per hop)
 │      └─ audit SSH_CONNECT
 │
 ├─ STAGE 2: target leg
 │    ssh           → connect_hop() over the last hop
 │    winrm         → LocalTunnel(last hop → endpoint) then WinRMChannel
 │    nested-winrm  → WinRMChannel to the jump, then NestedWinRMChannel
 │    (failure here → fall back to the last authenticated hop, see §9)
 │
 ├─ daemon.SessionServer.serve_forever()
 │    ├─ bind 127.0.0.1:<ephemeral>, write descriptor (mode 0600) with a token
 │    ├─ start the idle watchdog (15 s poll)
 │    └─ run operator_shell in the foreground
 └─ on close: tunnels → channels → hops torn down in reverse; credentials wiped
```

### 6.2 Run — executing an operation

```
ac run win-app01 install-package -p package=agent.msi --confirm
 │
 ├─ daemon.attach()              read descriptor, ping, get a client
 ├─ client.call("run_operation", …)  one JSON line over loopback
 │
 └─ SessionServer.do_run_operation → Engine.run_operation
      ├─ catalog lookup + applies_to(host)      → ConfigError if not permitted
      ├─ session.permits(op)                    → PermissionRequired if not in --ops
      ├─ operation_variables()                  → missing param → ConfigError
      ├─ _check_permission()                    → gated & unconfirmed → refuse,
      │                                            quoting the rendered commands
      ├─ for each selected step:
      │    ├─ template.render()                 strict; unresolved → TemplateError
      │    ├─ safety.check()                    BLOCKED → refuse; CONFIRM → needs --confirm
      │    ├─ session.exec()                    over the live channel
      │    ├─ evaluate()                        exit code / stdout expectations
      │    └─ on failure: collect() + hint_for(exit_code)
      ├─ write <session>-NN-<operation>.md      shareable summary
      └─ audit operation.start / step.* / operation.end
```

The engine **never remediates**. It observes reliably and returns structured
data; deciding what a failure means is the agent's or the operator's job.

### 6.3 Command lifecycle inside one step

```
step.run (YAML)
  → render {{placeholders}}
  → safety.classify
  → pshell.wrap_script      (PowerShell only: sets a resolved exit sentinel)
      SSH:   powershell.exe -EncodedCommand <base64 UTF-16LE>
      PSRP:  invoked in the held RunspacePool, success stream via Out-String
      nested: Invoke-Command on the jump, credential bound as a PSRP parameter
  → ExecResult (self-redacting, clamped to 20 000 chars head+tail)
  → evaluate() against `expect:`
```

---

## 7. Authentication flow

Authentication happens **per hop**, and nothing is stored.

```
                    ┌──────────────────────────────────────────┐
                    │ credentials.select_prompter()            │
                    │   stdin is a TTY?      → TerminalPrompter│
                    │   Windows + pywin32?   → CredUI dialog   │
                    │   neither              → Unavailable(fail)│
                    └───────────────┬──────────────────────────┘
                                    │ human types it
                 ┌──────────────────▼───────────────────┐
                 │ CredentialStore (in-memory, per node)│
                 │   register(secret) → redact registry │
                 └──────────────────┬───────────────────┘
                                    │
        SSH hop                     │                    Windows hop
 ┌──────────────────────┐           │           ┌────────────────────────────┐
 │ 1 agent keys         │           │           │ username qualified to      │
 │ 2 publickey          │◄──────────┴──────────►│   DOMAIN\user              │
 │   (PartialAuth →)    │                       │ NTLM over the tunnel       │
 │ 3 password           │                       │   provider: auto|sspi|python│
 │ 4 keyboard-interactive (MFA/OTP verbatim)    │ message encryption: auto   │
 └──────────────────────┘                       └────────────────────────────┘
                                    │
                       on success → note_authenticated()
                       on failure → creds.discard(node)  (never retried)
```

Key properties:

- **`key+password` is a real chain**, not a fallback: OpenSSH
  `AuthenticationMethods publickey,password` answers the key with a *partial
  success* naming what it still wants, and the password completes the login. If
  the key is rejected first, the error says so explicitly — because no password
  can succeed after that, and the usual cause is a wrong username.
- **Domain qualification** turns `jumpuser` into `corp\jumpuser` when `domain:` is
  set, on *every* node kind (AD-joined Unix via SSSD/winbind accepts it too). A
  username that already carries a domain is left alone, and a `domain:` that
  contradicts it is a load-time error rather than a silent discard.
- **MFA challenges pass through verbatim.** A single hidden prompt containing the
  word "password" is answered from the stored credential; anything else goes to
  the human with the server's own wording.
- **Host keys** are checked against `known_hosts`. A *changed* key is always
  fatal. An *unknown* key is accepted and recorded under the default
  `accept-new` policy; `AC_HOST_KEY_POLICY=strict` refuses it.
- **NTLM provider selection** (`auth.ntlm_provider`, default `auto`): a tunnelled
  or pre-established leg uses Windows SSPI; a *direct* (no-bastion) leg uses the
  pure-Python provider, because a client-side "Restrict NTLM outgoing" Group
  Policy makes SSPI fail locally with `SEC_E_LOGON_DENIED` before the server ever
  sees the credential. See [SECURITY.md](SECURITY.md#35-ntlm-provider-selection) —
  this deliberately steps around a corporate control and is worth knowing about.

---

## 8. Authorization model

There is no user database and no RBAC inside this tool. Authorization is the
**intersection of five independent gates**, each of which can only subtract:

| # | Gate | Where | Refuses |
|---|---|---|---|
| 1 | **Reachability** | `routegraph` / `route` | A host with no declared route, an ambiguous route, or one crossing an environment boundary |
| 2 | **Catalogue binding** | `Operation.applies_to(host)` | An operation whose `host_ids`/`tags` do not include this host |
| 3 | **Session allow-list** | `ac connect --ops a,b` → `Session.permits` | Any operation not named at connect time |
| 4 | **Permission gate** | `Operation.is_gated` + `--confirm` | A gated or destructive operation without explicit approval, quoting the rendered commands |
| 5 | **Command deny-list** | `safety.check` on every rendered command | `BLOCKED` outright (no override); `CONFIRM` without confirmation |

Plus two structural constraints that behave like authorization:

- **The target never instructs the agent.** Instructions live in the repo
  (`operations.yaml`, briefs, campaigns), reviewed and version-controlled. A
  compromised host cannot supply work to a privileged, credentialed session.
- **A degraded session authorizes nothing.** If the target leg failed and the
  session is held at a hop, `Session.operations()` returns an empty list and
  `Session.exec` refuses unless the caller explicitly says it knows it is on the
  hop (only the operator's own prompt does).

The real access control is still the estate's: `sshd_config`, firewall rules,
WinRM ACLs, and the account's own rights. This tool's gates constrain *this
tool*; they do not constrain a human with a shell. That distinction is stated
plainly in [SECURITY.md](SECURITY.md#24-explicitly-out-of-scope).

---

## 9. Session lifecycle and degraded mode

```
      build_session ──► connect ──► [serving] ──► close
                          │                        │
                          │  target leg failed     │  tunnels → channels → hops
                          ▼                        ▼  reversed, credentials wiped
                    degraded (held at last
                    authenticated hop)
                          │  :retry at the prompt
                          └──► recovered (session.recovered)
```

**Degraded / fallback** exists because throwing away three typed passwords
because the last leg refused is the wrong answer. The chain stays up, the
operator gets a prompt on the machine that was *supposed* to reach the target —
which is where the useful diagnosis lives — and `:retry` re-attempts the final
leg at no credential cost. While degraded:

- catalogue operations are not offered at all,
- `ac exec` and `run_operation` are refused,
- the prompt is visibly marked `[node · FALLBACK]`,
- `session.degraded` and `session.recovered` audit events bracket the period.

`EphemeralSession` (used by `ac rdp` / `ac tunnel` / `ac shell` when no session
is live) deliberately disables fallback: a one-shot command that silently ran
somewhere other than where it was aimed would be a lie.

**Idle timeout** defaults to 1800 s (`--idle-timeout 0` disables). A watchdog
thread polls every 15 s and closes the session, wiping credentials, on expiry.

---

## 10. Request lifecycle over the session socket

```
client                                   server (inside the ac connect process)
──────                                   ──────────────────────────────────────
read %LOCALAPPDATA%/access_control/
     sessions/<host>.json   (mode 0600)
     → {port, token, pid, session_id}
                     │
   connect 127.0.0.1:<port>              accept (max 8 backlog, 1 s poll)
   send {token, method, params}\n        ─► token compared with compare_digest
                                            → dispatch do_<method>(**params)
   read one line, ≤ 8 MiB               ◄─ {ok: true, result: …}\n
                                            or {ok:false, error, error_type}
```

Methods: `ping`, `status`, `preflight`, `operations`, `reload`, `preview`,
`run_operation`, `run_command`, `fetch_log`, `upload`, `download`, `open_tunnel`,
`close_tunnel`, `credentials_for`, `close`. Full reference:
[implementation/session-protocol.md](implementation/session-protocol.md).

Two deliberate behaviours: `credentials_for` returns a **username only** —
passwords never cross this socket — and `close` writes its report *before*
tearing the listener down, so `ac disconnect` receives the status it is owed
instead of a connection error.

---

## 11. Trust zones and security boundaries

```
╔═════════════════════════════════════════════════════════════════════╗
║ ZONE 0 — the operator's workstation                                 ║
║   Trust: full. Holds plaintext credentials in process memory,       ║
║   the session token, private keys, known_hosts and the audit trail. ║
║   Boundary to the rest of the machine: 0600 descriptor + loopback.  ║
║   NOT a privilege boundary — anything running as this user can      ║
║   read the descriptor and drive the session.                        ║
╠═════════════════════════════════════════════════════════════════════╣
║ ZONE 1 — bastion (SSH)                          [network boundary]  ║
║   Authenticated with key+password. Sees: SSH protocol traffic and   ║
║   direct-tcpip forward requests. Does NOT see the WinRM payload     ║
║   (message-level encryption inside the tunnel) or later passwords.  ║
╠═════════════════════════════════════════════════════════════════════╣
║ ZONE 2 — Windows jump server                    [platform boundary] ║
║   Authenticated with NTLM over the forwarded port. On a nested      ║
║   route it EXECUTES Invoke-Command, so it holds the target's        ║
║   credential in memory for the duration. Bound as a PSRP parameter, ║
║   never interpolated into script text (PowerShell 4104 logging).    ║
╠═════════════════════════════════════════════════════════════════════╣
║ ZONE 3 — target server                          [blast radius]      ║
║   Runs the rendered commands with the target account's rights.      ║
║   Never supplies instructions back to the agent.                    ║
╠═════════════════════════════════════════════════════════════════════╣
║ ZONE 4 — the agent (Claude) / any thin client                       ║
║   Sees: host ids, rendered commands, stdout/stderr, exit codes,     ║
║   collected logs, audit summaries. Never sees a credential, and     ║
║   cannot drive a prompt. Its only interface is `uv run ac …`.       ║
╚═════════════════════════════════════════════════════════════════════╝
```

Boundary properties worth stating explicitly:

- **Loopback only.** Tunnels bind `127.0.0.1`; the session socket binds
  `127.0.0.1`. Nothing this tool opens is reachable from the network.
- **Encryption in depth.** SSH protects the tunnel; pypsrp's `encryption="auto"`
  keeps the WinRM payload sealed *inside* it, so the bastion cannot read the
  PowerShell traffic it forwards.
- **Credential separation.** Each hop's credential is stored under that node's id
  and used only for that node. A rejected credential is discarded, not retried.
- **The audit trail is written by the audited process.** It is excellent for
  "what did the agent do and why did it fail"; it is not tamper-evident and is
  not a chain-of-custody artefact.

---

## 12. Integration points

| Integration | Direction | Mechanism |
|---|---|---|
| SSH servers (bastion, Unix targets) | outbound | Paramiko, port from the declared edge |
| Windows WinRM/PSRP | outbound | pypsrp over a loopback forward (or direct), NTLM, `encryption=auto` |
| Windows RDP | outbound, human | `mstsc` against the local end of a forward; optional `cmdkey` staging |
| Windows Credential UI | local | `win32cred.CredUIPromptForCredentials` (pywin32) |
| SSH agent | local | `paramiko.Agent()` when `auth.method: agent` |
| `known_hosts` | local file | `~/.ssh/known_hosts`, or `AC_KNOWN_HOSTS` |
| SIEM / log collection | outbound, pull | JSONL under `logging.path`; canonical `timestamp`/`agentId`/`sessionId`/`action` fields need no transform |
| Claude / any agent | local | `Bash(uv run ac …)` with `--json`; one permission surface |
| Change management | manual | `brief.change_ref` recorded in the trail and every report |

There are **no** inbound network integrations, no database, no message queue, no
cloud service and no telemetry. The only persistent state is on the local
filesystem (see [CONFIGURATION.md](CONFIGURATION.md#1-filesystem-locations)).

---

## 13. Concurrency model

| Concern | Approach |
|---|---|
| One session per host | Enforced by the descriptor file; `ac connect` refuses a second one |
| Multiple clients per session | `SessionServer` spawns a thread per request; `Session` state guarded where shared |
| Tunnel connections | One thread per accepted connection, pumped with `select` |
| PSRP pipelines | Run on a worker thread so a wall-clock timeout can stop them (`pypsrp` has none) |
| Campaign fan-out | `ThreadPoolExecutor`, bounded by `max_parallel` (default 8); one host per target |
| Credential store | `threading.RLock` |
| Redaction registry | `threading.RLock`, process-global |
| Audit writes | `threading.Lock` + `flush` + `fsync` per record |

The PSRP channel serialises `exec` under its own `RLock`, so two clients issuing
commands against the same Windows session queue rather than interleave.

---

## 14. Error handling architecture

Every error raised by this package derives from `AccessControlError`, which
derives from `RedactingError` — so **the message is scrubbed of registered
secrets before it can be printed anywhere**.

| Exception | Raised when |
|---|---|
| `ConfigError` | Inventory/catalogue/brief is invalid |
| `RouteError` | No declared path, ambiguous, or untraversable |
| `CredentialError` | No prompter, cancelled, or empty entry |
| `ConnectionFailed` | A hop or target could not be reached or authenticated |
| `ChannelUnavailable` | The requested channel cannot do this (e.g. upload through a nested leg) |
| `SessionError` | Session missing, expired, closed, or in the wrong state |
| `PermissionRequired` | Gated operation or `CONFIRM` command without approval |
| `CommandBlocked` | Matched the never-run list |
| `TemplateError` | A step template referenced an unsupplied variable |
| `StepFailed` | A step ran but did not meet its expectation |

Conventions the whole codebase follows:

- **Messages say what to do next**, not just what went wrong.
- **Teardown never raises** — `close()`, `cleanup()` and `finally` blocks swallow
  their own errors so they cannot mask the real one.
- **Anything not an `AccessControlError`** is a bug or a library failing in a way
  this tool has no message for: the operator gets one clean line and the full
  traceback is appended to `<log dir>/errors.log` by
  `logging_setup.record_unexpected`.
- **Library chatter is captured, not silenced.** Paramiko/pypsrp/spnego logging
  goes to `<log dir>/transport.log` through a redacting filter, so a benign
  `unhandled type 3` never lands in the middle of a password prompt.

---

## 15. Observability

| Signal | Location | Notes |
|---|---|---|
| Audit trail | `<log dir>/<trace_id>.jsonl` | One JSON object per action, fsynced |
| Session summary | `<log dir>/<trace_id>.md` | Hop chain, timeline, step table, errors |
| Operation report | `<log dir>/<session>-NN-<operation>.md` | Also returned in-band as `summary` |
| Transport log | `<log dir>/transport.log` | Paramiko/pypsrp/spnego, redacted |
| Unexpected tracebacks | `<log dir>/errors.log` | Written by `record_unexpected` |
| Live status | `ac status [host]` | Route, idle timer, tunnels, authenticated nodes |
| Execution trace | `ac timeline <session-id>` | Ordered actions with durations |
| Health of the workstation | `ac doctor` | Config, imports, keys, prompting, routes |
| Reachability | `ac probe <host> [--deep]` | Per-port, plus TCP-forwarding verdict |

There is no metrics endpoint, no tracing exporter and no alerting. Alerting is
expected to come from ingesting the JSONL trail — see
[OPERATIONS.md](OPERATIONS.md#42-signals-worth-alerting-on).

---

## 16. Deployment architecture

There is nothing to deploy on servers. A deployment is:

```
operator workstation (Windows 11 / macOS / Linux)
  ├─ Python 3.12+ and uv
  ├─ this repository (config/ committed and shared)
  ├─ ~/.ssh/  private keys + known_hosts        (per user, never in the repo)
  └─ %LOCALAPPDATA%\access_control\
       ├─ logs/       audit trails, summaries, transport.log, errors.log
       └─ sessions/   one 0600 descriptor per live session
```

Scaling is per-operator, not per-server: two people running the tool are two
independent clients with their own credentials and their own trails. There is no
shared state between them beyond the committed YAML.

See [INSTALLATION.md](INSTALLATION.md) and
[OPERATIONS.md](OPERATIONS.md#3-running-in-production).

---

## 17. Known architectural limits

1. **One Windows jump server maximum** — deeper nesting would pass a credential
   through an intermediate script.
2. **SSH cannot follow WinRM** in a chain.
3. **WinRM double-hop** — a remote session cannot forward credentials onward, so
   a target cannot reach a UNC share on its own behalf. Mitigated by requiring a
   server-local package share; otherwise needs CredSSP or upload-then-install.
4. **Kerberos does not work over the tunnel** — the endpoint is a loopback
   address with no matching SPN. NTLM with message encryption is used instead.
5. **An operator must be present**, and the `ac connect` window must stay open —
   the direct consequence of never storing a credential.
6. **Not idempotent.** This is procedural automation, like a human runbook.
7. **The route graph and command policy are advisory**, enforced client-side.
8. **The audit trail is not tamper-evident.**

Each of these is expanded, with the alternative that solves it, in
[guides/features.md](guides/features.md#honest-limitations) and
[production-readiness.md](production-readiness.md).
