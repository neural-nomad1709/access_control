# access-control

Reach servers through a chain of bastion and jump hosts and run **audited,
permission-gated operations** on them — driven from the CLI, by a human or by an
agent (every command takes `--json`).

```
Local Machine
   ↓ SSH  (key + password, prompted)
Bastion Host            environment: QA, zone: Internal
   ↓ tunnelled PowerShell Remoting
Jump Server (Windows)   environment: QA
   ↓ Invoke-Command with explicit credentials
Target Server (Windows)
   ↓
Operations: install packages, patch, restart services, collect logs
```

Linux / Unix / AIX targets use SSH the whole way; Windows targets use WinRM.

---

## Business purpose

Estates that matter are segmented: production servers are reachable only through
a bastion, often then through a Windows jump server. That is deliberate, and it
makes routine work expensive — every install, patch or diagnostic costs an
operator a chain of manual logins, and nothing about it is recorded in a form
anyone can query afterwards.

The obvious fix is to let an agent do it. The obvious risk is that an agent with
a credentialed path to production is exactly the thing you do not want to build
carelessly.

This tool is the careful version:

- **credentials are typed by a human, at every hop, and stored nowhere**;
- **connectivity is declared, never discovered** — a target with no declared edge
  simply cannot be reached;
- **capability is catalogued** — an agent can run nothing that is not in a
  reviewed YAML file, bound to specific hosts;
- **destructive actions are gated** — they refuse to run until an operator
  approves the fully rendered command;
- **everything is audited** — one JSON record per action, fsynced, SIEM-ready;
- **failures come back diagnosed** — the nominated logs, the exit code and a
  human-written hint, which is what makes "read the logs and fix it" tractable.

## Key capabilities

| | |
|---|---|
| **Declared multi-hop routing** | Every permitted hop lives in `inventory.yaml` with an explicit port. Ambiguous routes are refused; a route may not cross an environment boundary |
| **In-process tunnels** | `ssh -L`, built and torn down with the session. No external process, no port to coordinate |
| **Zero-storage credentials** | Prompted per hop, held in memory, wiped on disconnect, scrubbed from every output |
| **Windows over WinRM, not RDP** | Real output, error and warning streams plus a resolved exit code — including MSI codes like 1603 and 3010 |
| **Operation catalogue** | Reusable capabilities with expectations, timeouts and failure diagnostics, bound to hosts by id or tag |
| **Task briefs** | The work order for one host, validated offline before anything connects |
| **Campaigns** | One reviewed brief fanned out across many hosts' live sessions |
| **Preflight, including identity** | Proves you are on the machine you think you are — the failure a port forward makes silent |
| **Command deny-list** | Catastrophic commands refused outright; state-changing ones require confirmation |
| **Audit trail and timeline** | Per-run agent and session ids, canonical action records, and a readable summary per session and per operation |
| **Interactive handoff** | `ac rdp`, `ac shell`, `ac tunnel` — for the jobs a human should do |

## Architecture summary

```
ac connect (operator's terminal)          ac run / exec / verify / brief …
  prompts per hop, holds the session  ◄── loopback socket + token ── thin clients
  gives you a prompt on the host              (never see a credential)
        │
   Session ── Engine ── safety deny-list ── AuditLog → *.jsonl / *.md
        │
   Route (declared graph) → SSH hops → local forward → WinRM/PSRP → nested Invoke-Command
```

`ac connect` is the only command that touches a password, and it must run in a
real terminal. Everything else attaches to that session by host id. Full detail:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Why not RDP for automation?

RDP is a *display* protocol. It carries pixels — there is no stdout, no stderr,
no exit code. An install that fails over RDP gives you a bitmap of an error
dialog, which an agent cannot reliably read, diagnose, or act on.

So this tool keeps the hop chain exactly as your network requires, but drives
Windows hosts over **PowerShell Remoting (WinRM, port 5985) tunnelled through the
SSH bastion**. That returns real output, error, and warning streams plus exit
codes — which is precisely what makes "read the logs and fix the problem"
possible.

**RDP is still here**, for the job it is genuinely good at: `ac rdp <host>` opens
a tunnel and launches `mstsc` so a *human* can take over a session. That also
serves as the bootstrap — if WinRM is disabled on a host, RDP in once, run
`Enable-PSRemoting -Force`, and it is automatable from then on.

---

## Install

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```powershell
uv sync --extra dev
uv run ac doctor
```

Full prerequisites, platform notes and validation steps:
[docs/INSTALLATION.md](docs/INSTALLATION.md).

## Quick start

```powershell
# 1. Describe your hosts (copy the example, then edit)
copy config\inventory.example.yaml config\inventory.yaml

# 2. See what is declared, and what can actually be reached
uv run ac hosts
uv run ac routes                     # every declared hop
uv run ac routes target1             # resolve one route
uv run ac probe target1 --deep       # what actually answers

# 3. Open a session. Passwords are prompted HERE, in your terminal, per hop.
uv run ac connect target1 --ops install-package

# 4. Prove you are on the right machine, then work
uv run ac verify target1 --expect-hostname TARGET1
uv run ac preview target1 install-package -p package_share='D:\pkg' -p package=agent.msi
uv run ac run     target1 install-package -p package_share='D:\pkg' -p package=agent.msi --confirm

# 5. Close out — prints a full status report before disconnecting
uv run ac status
uv run ac timeline <session-id>      # what happened, in order
uv run ac disconnect target1
```

Never used it before? **[docs/guides/runbook.md](docs/guides/runbook.md#part-1--running-it-step-by-step)**
walks the whole loop end to end.

## Credentials

**Nothing is stored.** Passwords are prompted at every hop, held only in the
memory of the session process, and wiped on disconnect. They are never written to
disk, never rendered into a logged command, and are scrubbed from all output.

Because a tool invoked by Claude has no interactive terminal, prompting happens
out of band:

| Mechanism | When |
| --- | --- |
| Terminal prompt (`ac connect`) | You start the session yourself — preferred |
| Windows credential dialog | Claude needs a hop and no session is live |

Never type a password into the chat. It would be recorded in the conversation.

## Configuration

Two YAML files, both safe to commit and share across the company — they contain
**no secrets**, only topology and the operations permitted on each host.

- `config/inventory.yaml` — one block per machine: who it is, and how it is reached.
- `config/operations.yaml` — the operation catalog, bound to hosts by `host_id`.

Each machine declares its own identity and, in `via:`, how it is reached and from
where. Addresses are **as seen from `from:`**, because the same machine looks
different depending on where you stand:

```yaml
hops:
  bastion1:
    kind: ssh
    username: operator            # identity lives with the machine, and only here
    domain: prod
    auth: {method: key+password, key_file: ~/.ssh/id_rsa}
    via:
      from: local              # `local` is the operator's own machine
      hostname: bastion1.example.net
      port: 2222               # ports are mandatory, never defaulted
      protocol: ssh

  JumpServer01:
    kind: windows
    username: jumpuser
    domain: corp
    auth: {transport: ntlm}
    via:
      from: bastion1           # addresses below are as seen FROM bastion1
      automation:  {hostname: 10.20.4.11, port: 5985, protocol: winrm}
      interactive: {hostname: 10.20.4.11, port: 3389, protocol: rdp}
```

`automation` and `interactive` are separate fields because RDP carries pixels and
cannot return an exit code — declaring it as automation is rejected at load time.

**Connectivity is declared, never discovered.** A target with no declared edge
fails immediately — the tool will not fall back to a direct connection, and will
not retry into a path that was never permitted. A route may not cross an
environment boundary, so a QA bastion cannot become a way into production.

Because connectivity is part of the machine's own block, commenting a machine out
takes its route with it, and there is no second place to keep in sync. A standalone
`routes:` list and the per-host `path: [bastion1, jump1]` shorthand still load and
compile to the same graph, but cannot be combined with `via:` in one file.

Every setting, default and environment variable:
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Deployment

There is nothing to deploy on the servers. A deployment is one operator, one
workstation, one checkout:

```
workstation
  ├─ Python 3.12+ and uv
  ├─ this repository (config/ committed and shared)
  ├─ ~/.ssh/  keys + known_hosts          (per user, never in the repo)
  └─ %LOCALAPPDATA%\access_control\
       ├─ logs/      audit trails, summaries, transport.log, errors.log
       └─ sessions/  one 0600 descriptor per live session
```

Running it in production — monitoring, backup, maintenance and upgrades — is in
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Documentation

| Guide | Contents |
| --- | --- |
| [docs/README.md](docs/README.md) | **The map — start here if you are not sure** |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Prerequisites, setup, validation |
| [docs/guides/runbook.md](docs/guides/runbook.md) | **Part 1: running it step by step. Part 2: troubleshooting by symptom** |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every setting, default and environment variable |
| [docs/guides/operations-guide.md](docs/guides/operations-guide.md) | Adding a host, writing an operation |
| [docs/guides/instructions-guide.md](docs/guides/instructions-guide.md) | Task briefs, campaigns, and the rules for instructing the agent |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flows, auth and authz, trust zones |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, controls, hardening, incident response |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Production use, monitoring, backup, upgrades |
| [docs/CLAUDE_PRODUCTION_GUARDRAILS.md](docs/CLAUDE_PRODUCTION_GUARDRAILS.md) | Deploying Claude against a live production session |
| [docs/guides/features.md](docs/guides/features.md) | Every feature, and how it compares to plink, Ansible, mRemoteNG, Teleport and PAM tools |
| [docs/implementation/](docs/implementation/README.md) | Module contracts, CLI reference, audit events, wire protocol |
| [docs/guides/testing.md](docs/guides/testing.md) | Test strategy and the two end-to-end loops |
| [STATUS.md](STATUS.md) · [BugFixNchange.md](BugFixNchange.md) | Current state, and what is fixed or open |

**Deciding whether this is the right tool?** Start with
[docs/guides/features.md](docs/guides/features.md). It is candid about where
Ansible, Teleport or plain `plink` is the better answer.

## Tunnels

Everything past the first bastion rides a tunnel, and **the tool builds its own**
— a loopback listener anchored at the already-authenticated SSH hop, with each
connection getting its own `direct-tcpip` channel. That is `ssh -L`, in-process:
no external tunnel to start, no port to coordinate, and it is torn down with the
session.

If you would rather keep a forward you already manage (mRemoteNG's, or your own
`ssh -L` / `plink -L`), declare its local end with `preestablished: true` and the
tool dials that instead.

`ac tunnel <node>` holds a forward open on its own, through the same
authenticated chain, for any client to use:

```powershell
uv run ac tunnel JumpServer01
# 127.0.0.1:53001  ->  10.20.4.11:3389  (JumpServer01)
```

**The one thing that stops all of it** is `AllowTcpForwarding no` on a bastion.
It presents as an unreachable target, so `ac probe` asks the question directly
and reports `tcp forwarding: yes|NO` per bastion — there is no client-side
workaround, and knowing that early saves an argument with the wrong team.

## Instructing the agent

`operations.yaml` says what *may* be run. A **task brief** says what to do on one
host this time — the operations in order, what must be true before starting, what
"done" looks like, and the rules the agent must obey.

```powershell
# Before the change window — connects to nothing
uv run ac brief validate config\briefs\example-windows-install.yaml
uv run ac brief show     config\briefs\example-windows-install.yaml

# In the window
uv run ac connect win-target02
uv run ac verify  win-target02 --expect-hostname WIN-TARGET02
uv run ac brief run config\briefs\example-windows-install.yaml --confirm
```

Validation catches a wrong host, an unknown operation, a misspelled parameter, a
missing rollback block, or a brief that contradicts its own rules — before anyone
types a password.

To run one reviewed brief across several hosts, point a **campaign** at it. Each
host must already have a session; hosts without one are reported and skipped,
never connected to.

**`ac verify` is the check that matters most.** Every hop past the first arrives
over a local port forward, and a port number carries no identity: a stale tunnel
or one wrong digit produces a session that works perfectly against the wrong
server. It asks the machine its own name and refuses to proceed if it disagrees.

Start from [`config/briefs/TEMPLATE.yaml`](config/briefs/TEMPLATE.yaml); the full
rules are in
[docs/guides/instructions-guide.md](docs/guides/instructions-guide.md).

## The session window is a prompt

`ac connect` does not just hold a socket open. It gives you a prompt on the host,
and the prompt always names the machine the next command reaches:

```
corp\svc_deploy@win-app01.corp.net [win-target02] >
operator@bastion-staging.example.net [bastion-staging · FALLBACK] $
```

If the last leg fails but a bastion authenticated, the session is **held at that
hop** rather than thrown away — so you can diagnose from the machine that was
supposed to reach the target and type `:retry`, at no credential cost. While it
is a fallback, operations and `ac exec` are refused, because commands there would
run on the hop rather than the target.

## Reporting

Every operation produces a shareable end-to-end summary — result, host, route,
per-step table, and on failure the collected logs, the hint, and the exact
command to resume from. Print it with `ac run ... --summary`; it is also written
next to the audit trail and returned in the result so Claude can relay it
verbatim.

## Auditing

Each run gets its own identity — `AGT-20260812-3f9a1c` for the agent instance,
`SES-3f9a1c` for the session — so concurrent executions stay separable. The
suffixes are random, so ten sessions launched in the same second by independent
processes never collide. Name the agent yourself with `ac connect --agent-id`
or the `AC_AGENT_ID` environment variable. Every action is appended as one
JSON object:

```json
{"timestamp": "2026-08-12T09:15:22.431+00:00", "agentId": "AGT-20260812-3f9a1c",
 "sessionId": "SES-3f9a1c", "action": "SSH_CONNECT",
 "source": "JumpServer01", "target": "linux-app01", "result": "SUCCESS"}
```

`ac timeline <session>` renders the execution trace; `ac audit <session>` replays
every record. A readable Markdown summary — including the timeline — is written
when the session closes.

### Many sessions at once

One session is one host, held open by one `ac connect` process, so working
across ten servers means ten of them. Two arrangements, and they want different
agent ids:

| | Agent id | Tell them apart by |
|---|---|---|
| **One operator, ten servers** | One shared id — set `AC_AGENT_ID`, or pass the same `--agent-id` to all ten as a batch tag | `sessionId` + `host_id` |
| **Ten agents, ten servers** | One **per window** — `ac connect web01 --agent-id AGT-web01`. Do *not* put a shared `AC_AGENT_ID` in project settings; it would collapse all ten into one operator | `agentId` |

Either way, nothing needs configuring for correctness: an unnamed run still gets
a unique identity. `ac status` lists every live session regardless of which agent
opened it.

Location and retention are configurable, so trails can be collected for SIEM
ingestion:

```yaml
logging:
  enabled: true
  path: D:\Agent\Logs
  retention_days: 30
  level: INFO
```

The default is `%LOCALAPPDATA%\access_control\logs`, outside the repository on
purpose: this project sits in a OneDrive-synced folder and captured server output
must not be uploaded.

## Security considerations

- **Nothing is stored.** No keyring, no vault, no file, no environment variable
  by default. The cost is real and deliberate: an operator must be present and
  the session window must stay open. There are no unattended runs.
- **Five independent gates** decide whether something may run: the declared
  route, the catalogue's host binding, the session's `--ops` allow-list, the
  approval gate, and the command deny-list.
- **The route graph and the deny-list are advisory** — they constrain this tool,
  not the network. `sshd_config`, firewalls and account rights remain the real
  controls.
- **The session socket is a convenience boundary, not a privilege one.** It binds
  loopback and requires a token from a `0600` file, so another *user* cannot
  reach it — but anything running as you can.
- **The audit trail is written by the audited process.** Excellent for "what did
  the agent do and why did it fail"; not tamper-evident.
- **Before production**, work through
  [docs/SECURITY.md](docs/SECURITY.md#10-production-hardening-checklist) —
  `AC_HOST_KEY_POLICY=strict`, `environment` set on every node, a bounded idle
  timeout, and `AC_ALLOW_ENV_CREDENTIALS` unset everywhere.

## Safety

- Operations marked `requires_permission` or `destructive` refuse to run without
  an explicit confirmation, forcing the agent to ask you first.
- A deny-list blocks catastrophic commands (`Format-Volume`, `rm -rf /`,
  unconfirmed `Restart-Computer`) before execution.
- `--dry-run` renders the exact commands and connects to nothing.

## Troubleshooting

The full symptom index is
[docs/guides/runbook.md, Part 2](docs/guides/runbook.md#part-2--troubleshooting-by-symptom).
The five you are most likely to hit:

| Symptom | Cause | First move |
|---|---|---|
| `no live session for '<host>'` | Expected — credentials are never stored | Run `uv run ac connect <host>` in **your own** terminal, and leave it open |
| `No route defined between requested target and available bastion` | The target has no declared `via:` edge. Nothing was attempted | `ac routes` to see what is declared; add the leg |
| `tcp forwarding: NO` on a bastion | `AllowTcpForwarding no` in its sshd config | No client-side workaround. This needs the bastion's owner |
| WinRM `401` / "credentials were rejected" | Usually the username *form*, not the password | Set `domain:` on the node so it authenticates as `DOMAIN\user` |
| `HOST KEY MISMATCH` | The server was rebuilt — or the connection is being intercepted | **Nothing was sent.** Confirm with the server's owner before touching `known_hosts` |

## FAQ

**Do I have to keep a terminal open?**
Yes, for the life of the session. It is the direct consequence of never storing a
credential, and it is the intended trade. `--idle-timeout` bounds it.

**Can it run unattended, at 03:00, with nobody watching?**
No. That needs stored credentials, which this design does not have. Use a PAM
product or a vaulted service account for that.

**Is `config/inventory.yaml` safe to commit?**
Yes — that is the point. It contains topology and identities, never secrets.
`.gitignore` blocks key material, and audit logs are written outside the repo.

**Can Claude see my password?**
No. Prompting happens on a TTY or in a Windows dialog; no CLI command and no
session method returns a secret. If a command says "no live session", it is
asking *you* to run `ac connect` — not asking for your password.

**Why WinRM instead of just RDP-ing in?**
RDP has no exit code. See [Why not RDP for automation?](#why-not-rdp-for-automation)

**Why does it refuse two routes of the same length?**
Because guessing which path to production to take is not a decision a tool should
make. Split the target into separate ids per path — the id becomes the selector.

**An operation failed halfway. Do I re-run the whole thing?**
No. Fix the cause, then `ac run <host> <op> --confirm --start-at <failed-step>`.
The failure report names the exact command.

**I edited `operations.yaml` and nothing changed.**
The running session holds the catalogue it started with. `ac reload <host>`. If
you edited the tool's *source*, reconnect.

**Is it idempotent, like Ansible?**
No. This is procedural automation, like a human runbook. If the question is "what
should this server look like", use Ansible — see
[docs/guides/features.md](docs/guides/features.md#when-to-use-something-else).

**How many hosts can a campaign drive?**
As many as have live sessions, bounded by `max_parallel` (default 8). A human has
to open each one, so this is a handful, not a fleet.
