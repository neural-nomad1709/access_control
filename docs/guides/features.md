# Features, and how they compare

A reference for every capability in this tool: what it does, how it works
underneath, why it was built that way, and how it compares to the alternatives
you could reasonably use instead.

**The honest summary first.** This is a narrow tool. It does one thing: lets an
agent (or a person) run *audited, permission-gated, procedural operations* on
servers reached through a chain of bastion and jump hosts, with credentials typed
by a human at every hop and nothing installed on the targets. For anything
outside that description — declarative configuration management, scheduled jobs,
enterprise credential vaulting, session recording — something else on this page
is a better answer, and each section says which.

---

## Contents

| # | Feature | Closest alternative |
|---|---|---|
| 1 | [Declared route graph](#1-declared-route-graph) | Hardcoded hop chains in scripts; Ansible `ProxyJump` |
| 2 | [In-process tunnels](#2-in-process-tunnels) | `ssh -L`, `plink -L`, mRemoteNG tunnel entries |
| 3 | [Zero-storage credentials](#3-zero-storage-credentials) | CyberArk/Delinea PAM, Ansible Vault, `plink -pw` |
| 4 | [Windows over WinRM, not RDP](#4-windows-over-winrm-not-rdp) | RDP + GUI robotics; PsExec; Ansible `winrm` |
| 5 | [Operations catalog](#5-operations-catalog) | Ansible playbooks, Rundeck jobs, shell scripts |
| 5b | [Task briefs and preflight](#5b-task-briefs-and-preflight) | Change tickets, runbook wiki pages, "just tell it what to do" |
| 5c | [Campaigns — one brief, many hosts](#5c-campaigns--one-brief-many-hosts) | Ansible inventory groups, a `for` loop, doing it by hand |
| 6 | [Failure diagnosis](#6-failure-diagnosis) | Reading logs by hand |
| 7 | [Command safety policy](#7-command-safety-policy) | `sudoers`, PAM command filtering, nothing |
| 8 | [Audit trail and identity](#8-audit-trail-and-identity) | Teleport session recording, PAM, `script(1)` |
| 9 | [Session daemon](#9-session-daemon) | `ssh` ControlMaster, `tmux`, re-authenticating |
| 9b | [The operator prompt and hop fallback](#9b-the-operator-prompt-and-hop-fallback) | Opening a second connection and retyping everything |
| 10 | [Interactive handoff](#10-interactive-handoff) | mRemoteNG, `mstsc`, RDP managers |
| 11 | [The CLI](#11-the-cli) | Raw shell calls from an agent |
| 12 | [Secret redaction](#12-secret-redaction) | Hoping |

Then: [head-to-head comparison](#head-to-head), [when to use something
else](#when-to-use-something-else), and [honest
limitations](#honest-limitations).

---

## 1. Declared route graph

### What it does

Every permitted hop is declared in `inventory.yaml`. Asking for a target resolves
a path through those declarations, or fails.

```yaml
hops:
  bastion1:
    kind: ssh
    username: operator
    via: {from: local, hostname: bastion1.example.net, port: 2222, protocol: ssh}

  JumpServer01:
    kind: windows
    username: jumpuser
    domain: corp
    via:
      from: bastion1
      automation:  {hostname: 10.20.4.11, port: 5985, protocol: winrm}
      interactive: {hostname: 10.20.4.11, port: 3389, protocol: rdp}
```

### How it works

`routegraph.py` holds directed edges and nothing else. Resolution is
breadth-first search over those edges — no sockets, no probing, no inference. The
result is validated before anything connects: traversability, protocol
compatibility, environment boundaries.

The critical property is what happens when there is no edge:

```
ERROR: No route defined between requested target and available bastion.
  requested target : linux-app01
  reason           : no declared edge reaches it
Routes are never discovered; a direct connection will not be attempted.
```

There is no fallback path in the code. `Session.connect` has no branch that
skips resolution.

**Each edge carries the address as seen from its source.** This matters more than
it sounds: the same jump server is `10.20.4.11:3389` from the bastion and
`localhost:44001` on your laptop where a tunnel terminates. Most tools model a
host as having *one* address, which forces you to pick which vantage point is
"real" and paper over the rest.

Validation happens at **load** time, not connect time. An untraversable topology
is a config error you see immediately, not a surprise three passwords into a run.

### Why built this way

Two reasons.

**Segmentation is policy, not topology.** Whether the QA bastion can reach a
production host is a firewall decision made by someone else. A tool that
*discovers* connectivity by probing will eventually find a path that exists by
accident and use it. Declaring the graph means the tool can only do what someone
wrote down.

**Failing fast beats retrying.** A missing route produces an immediate, specific
error naming what to add. The alternative — attempting a direct connection,
timing out, retrying — wastes minutes and produces a diagnosis ("connection
timed out") that points at the network rather than at the config.

### Compared to the market

| Approach | How routing works | Trade-off |
|---|---|---|
| **Shell scripts** | Hop chain hardcoded per script | Works, but the topology lives in N places and drifts. No validation. |
| **Ansible** | `ansible_ssh_common_args: -J bastion` per host or group | Mature and flexible, but it is an SSH argument string — no validation, no environment boundaries, and no concept at all for a WinRM hop behind a jump server. |
| **Teleport** | Server-side RBAC decides what you can reach | **Genuinely better** if you can deploy it: certificate-based, centrally enforced, per-user. Requires a proxy and agents on every node. |
| **CyberArk / BeyondTrust** | Central policy, session brokered by the vault | **Genuinely better** for compliance. Requires the platform, licences, and a project. |
| **This tool** | Declared edges in a shared YAML file, resolved client-side | No infrastructure, works today, version-controlled with the repo. But it is *advisory* — it constrains this tool, not the network. Someone with SSH can still go around it. |

**Be clear about that last point.** The route graph is a correctness and safety
mechanism, not a security boundary. It stops an agent from wandering; it does not
stop a determined human. If you need enforcement, you need Teleport or a PAM
product, and the bastion's own `sshd_config` remains the real control.

---

## 2. In-process tunnels

### What it does

Builds the port forwards that every hop past the first depends on, without any
external process.

### How it works

A tunnel is a loopback listener anchored at an **already-authenticated SSH hop**.
Each accepted connection opens its own `direct-tcpip` channel on that hop's
existing transport, and bytes are pumped both ways. This is precisely what
`ssh -L` does, running inside the same process that already holds the
authenticated connection.

```
ac connect win-app01
  ├─ authenticate  local -> bastion1                    (SSH, prompted)
  ├─ open tunnel   127.0.0.1:53001 -> jump:5985         (direct-tcpip via bastion1)
  ├─ authenticate  PSRP over that tunnel                (NTLM)
  └─ Invoke-Command jump -> win-app01                   (no tunnel needed)
```

Properties that follow:

- **Lifetime is the session's.** Opened on connect, torn down in reverse on
  disconnect — including on failure. Nothing is left listening.
- **Ephemeral ports by default**, so parallel sessions never collide over a
  hardcoded 44001.
- **Bound to `127.0.0.1` only.** A forward to a production server must not be
  reachable from the rest of the network.
- **The jump → target leg uses no tunnel at all.** It is an `Invoke-Command`
  executed *by* the jump server; the traffic never returns through us.

### The check that matters

`AllowTcpForwarding no` on a bastion makes every jump impossible, and there is no
client-side workaround. Worse, it *presents* as an unreachable target — which
sends people arguing with a firewall team about a rule that was fine.

So `ac probe` asks directly. It attempts a forward to a port that certainly is
not listening and reads the RFC 4254 channel-open failure code:

| Code | Meaning | Verdict |
|---|---|---|
| 1 `ADMINISTRATIVELY_PROHIBITED` | The server refused the *channel* | Forwarding is disabled. Nothing will work. |
| 2 `CONNECT_FAILED` | Channel accepted, destination declined | Forwarding works fine. |

Reported per bastion as `tcp forwarding: yes|NO`.

### Using a tunnel you already have

`preestablished: true` (implied by a loopback address) means a forward already
exists — mRemoteNG's SSH-tunnel entry, or your own `ssh -L`. The tool dials it
instead of building a second one on top.

```yaml
automation: {hostname: localhost, port: 45985, protocol: winrm, preestablished: true}
```

Use it when the tunnel is managed elsewhere or the bastion needs options this
tool does not expose. The cost: the forward's lifetime becomes your problem.

### `ac tunnel` — the forward on its own

```powershell
uv run ac tunnel JumpServer01
# 127.0.0.1:53001  ->  10.20.4.11:3389  (JumpServer01)
```

Same mechanism, exposed for any client: mRemoteNG, `mstsc`, a database tool, a
browser.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **`ssh -L` / `plink -L`** | Works, universally available, well understood. But it is a separate process with a separate lifetime — you start it, you remember to kill it, and a hardcoded local port collides when two people or two sessions want the same jump server. On Windows there is no `ControlMaster`, so you cannot reuse it for further commands either. |
| **mRemoteNG tunnel entries** | Excellent for humans — saved, named, one click. Not scriptable, and nothing links a tunnel's lifetime to a task's. |
| **sshuttle / VPN** | Transparent, no per-port config. Heavier, needs privileges, and routes far more than you intended. |
| **Teleport** | Tunnels are the product; no client config at all. Needs the infrastructure. |
| **This tool** | Zero setup, correct lifetime, no port collisions, and the forwarding-capability check. But it only forwards what a route declares, and it is Python rather than a 300 KB `.exe`. |

**When `plink -L` is the better answer:** you want a forward for something
unrelated to this tool, on a machine where installing Python is not worth it, or
the bastion needs SSH options this tool does not surface. That case is supported —
declare it `preestablished`.

---

## 3. Zero-storage credentials

### What it does

Prompts for a password at **every hop**, holds it in memory for the session, and
wipes it on disconnect. Nothing is written anywhere — no keyring, no vault, no
file, no environment variable.

### How it works

The awkward part is *where* the prompt appears. A tool invoked by an agent has no
controlling terminal, so `getpass` would read EOF and hang. And a password must
never be typed into a chat window, because that records it in the conversation
and sends it to a model provider.

So prompting bypasses the agent entirely:

| Prompter | Used when |
|---|---|
| Terminal (`getpass`) | stdin is a TTY — the operator ran `ac connect` themselves. Preferred. |
| Windows credential dialog | No TTY. A native dialog appears on the operator's desktop. |
| Neither available | Fails with instructions to run `ac connect`. Never silently degrades. |

The prompt names the machine, its environment and the identity:

```
== QA SSH bastion [QA] [corp\operator@bastion1.example.net:2222] ==
   password:
```

Supporting details that matter in practice:

- **Multi-factor chains.** `key+password` maps to OpenSSH's
  `AuthenticationMethods publickey,password` — the key is offered, the server
  returns a *partial success* naming what it still wants, and the password
  completes the login. Handling that correctly is not optional; your bastion is
  configured exactly this way.
- **MFA challenges pass through verbatim.** A keyboard-interactive OTP prompt is
  shown with the server's own wording, not a guessed one.
- **A rejected password is discarded**, not retried.
- **Domain qualification.** `domain: corp` turns `jumpuser` into `corp\jumpuser`
  before authentication. WinRM against a domain-joined host fails with a bare
  name, and the failure presents as a *wrong password* — which sends people
  resetting credentials that were fine.

### Why built this way

Because the requirement said so, and because the requirement is right for this
threat model. A tool that runs unattended against production needs stored
credentials; a tool that assists a present operator does not, and storing them
would add a theft target for no benefit.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **`plink -pw <password>`** | The password is in the process table and shell history. Every other process on the machine can read it while it runs. **This alone disqualifies it** for the stated requirement. |
| **SSH keys only** | Best where it works: no password to steal, agent forwarding handles chains. Breaks the moment a hop requires a password or MFA — which yours does. |
| **Ansible Vault** | Encrypted secrets in the repo, decrypted with one vault password. Good for unattended runs. But it *stores* the credentials, and one vault password unlocks everything. |
| **OS keyring (Windows Credential Manager)** | Convenient, OS-protected, survives restarts. Still storage: anything running as you can read it. This was the original design and was **dropped deliberately** in favour of prompting. |
| **CyberArk / Delinea / BeyondTrust** | **The right answer at enterprise scale**: central vault, rotation, checkout approval, session brokering, full compliance story. Costs money, needs a deployment project, and takes weeks not hours. |
| **This tool** | Nothing to steal at rest, per-hop separation, MFA passthrough. The cost is real: **an operator must be present, and the terminal must stay open.** No unattended scheduled runs. |

**That cost is the honest trade.** If you need a patch job at 03:00 with nobody
watching, this design cannot do it, and you want a PAM product or a service
account with a vault. Every other property here follows from choosing the
opposite.

---

## 4. Windows over WinRM, not RDP

### What it does

Drives Windows hosts with PowerShell Remoting tunnelled through the SSH bastion,
and uses RDP only to hand a desktop to a human.

### Why

**RDP is a display protocol.** It carries pixels, keystrokes and mouse movement.
There is no stdout, no stderr, no exit code. An installer that fails over RDP
gives you a bitmap of an error dialog.

The requirement is that the agent *reads the logs after each action and resolves
what it finds*. Over RDP that means screenshot-and-OCR robotics: it breaks when a
dialog moves, when a font changes, when a progress bar covers the text — and it
fails **silently**, reporting success because the pixels looked right.

PSRP returns real data:

```
exit_code    : 1603
ps_errors    : ["Product: MyApp -- Error 1603. Fatal error during installation."]
collected    : C:\Windows\Temp\MSI a1b2c.LOG  (last 120 lines)
hint         : Search the log for "Return value 3" -- that marks the failing action
```

That is the difference between an agent that can fix things and one that can
only report that something looked wrong.

### How it works

Two technical details worth knowing.

**Exit codes.** PowerShell has no single notion of "the exit code" — a native
tool sets `$LASTEXITCODE`, a cmdlet throws, `powershell.exe -EncodedCommand`
exits 0 regardless, and PSRP has no process exit code at all. So every script is
wrapped to resolve one and print it as a sentinel, which both channels parse
back out. On the nested leg two sentinels return — the jump server's and the
target's — and the last one wins, so the target's code is what you see.

**Credential passing on the nested leg.** The jump → target hop needs a
credential *on the jump server*. Interpolating it into script text would put it
in that server's PowerShell script-block log (event 4104) in clear text. So it
is bound as a **PSRP parameter** instead — the value travels as an argument
object, not as part of the logged script body.

**NTLM, not Kerberos.** The endpoint is a loopback tunnel address with no
matching SPN, so Kerberos cannot work. NTLM needs no SPN, and pypsrp's
message-level encryption keeps the payload encrypted inside the SSH tunnel.

**Which NTLM implementation, decided per route.** `auth.ntlm_provider` defaults
to `auto`: a leg reached through a bastion tunnel uses Windows SSPI, and a
*direct* leg (`via: {from: local}`, no bastion — a VPN or same-segment host) uses
spnego's pure-Python provider. That is not a preference, it is a workaround with a
specific cause: where the client's Group Policy sets *Restrict NTLM: Outgoing
NTLM = Deny* and the target is not allow-listed, SSPI refuses **locally** with
`SEC_E_LOGON_DENIED` before a packet is sent, and it looks exactly like a wrong
password. The pure-Python provider does not consult the LSA allow-list. The
bastion path is unaffected, because the exchange then originates to `127.0.0.1`.

Because the choice falls out of each server's own `via:`, a mixed fleet needs no
per-host tuning. It is also **a deliberate step around a corporate control**,
recorded in a `winrm.ntlm_provider` audit event — see
[../SECURITY.md](../SECURITY.md#35-ntlm-provider-selection) before making direct
routes the norm.

**Transport wedge recovery.** Pure-Python NTLM can desync its message-seal
counters, after which every sealed request returns an empty
`Bad HTTP response … Code: 400`. The counters live in the pypsrp client's auth
context, so the whole client is rebuilt (reusing the stored credential, no
re-prompt) and the same script re-run exactly once. That is safe because a wedge
rejects the request at the HTTP layer *before* the shell executes it.

### The fallback ladder

Decided by live probe, not assumption:

| # | Channel | When |
|---|---|---|
| 1 | WinRM / PSRP (5985) | Preferred |
| 2 | SSH (22) | Windows OpenSSH Server present — same path as Linux |
| 3 | WMI / DCOM (135) | WinRM closed but DCOM open — used to *enable* WinRM |
| 4 | Interactive RDP | Nothing else. The agent reports what it needs done. |

RDP doubles as the bootstrap: log in once, `Enable-PSRemoting -Force`, automated
from then on.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **RDP + GUI automation** (AutoIt, pyautogui, RPA tools) | The only option for genuinely GUI-only software. Brittle, unauditable, and fails silently. Use it when there is no alternative, not as a default. |
| **PsExec** | Simple, no WinRM needed. Copies a service binary to `ADMIN$`, needs SMB, sets off every EDR product, and gives you a text blob. |
| **Native `Invoke-Command`** | Exactly what this uses underneath. Doing it by hand means managing the tunnel, `TrustedHosts`, credential objects and exit-code resolution yourself. |
| **Ansible (`winrm` connection)** | Mature, idempotent, thousands of modules. **Better than this for repeatable configuration.** Harder to route through an SSH bastion to a Windows jump to a Windows target, and not designed for step-by-step agent reasoning about failures. |
| **This tool** | Real streams and exit codes through an arbitrary bastion chain, with automatic failure diagnosis. Not idempotent, and the module library is whatever you write. |

---

## 5. Operations catalog

### What it does

`config/operations.yaml` is the configurable list of what may be run, bound to
hosts by id or tag. Nothing outside it runs as an operation.

```yaml
- id: install-package
  tags: [windows]
  requires_permission: true
  params: [package_share, package]
  steps:
    - id: preflight
      run: |
        if (-not (Test-Path '{{package_share}}\{{package}}')) { exit 2 }
      expect: {exit_code: 0, stdout_contains: PREFLIGHT_OK}
    - id: install
      destructive: true
      timeout_s: 1800
      run: |
        $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
        exit $p.ExitCode
      on_failure:
        collect:
          - files: ['C:\Windows\Temp\MSI*.LOG']
          - eventlog: {log: Application, newest: 25, level: error}
        hints:
          "1603": Search the collected log for "Return value 3"
          "3010": Succeeded but needs a reboot. Do NOT re-run.
```

### Design decisions worth explaining

**Strict templating.** An unresolved `{{path}}` raises rather than rendering
empty. `Remove-Item {{path}}` silently becoming `Remove-Item` is how you delete
the wrong thing.

**Host binding is mandatory.** Every operation declares `host_ids` or `tags`, and
naming a host that does not exist is a hard error at load time. Getting this
wrong is how a patch job runs on the wrong machine.

**`--start-at` for retries.** After fixing a failure, re-running the whole
operation repeats work that succeeded — and for a destructive step that is
sometimes actively harmful. Resume from the step that failed.

**Gated by default.** An operation must opt *out* of asking permission.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **Ansible playbooks** | **The better tool for configuration management.** Idempotent (run twice, same result), thousands of maintained modules, huge community. This is not idempotent, and never claims to be — it is procedural, like a human runbook. |
| **Rundeck / AWX** | Job scheduling, RBAC, web UI, history. Needs a server and a project. Better if you want scheduled unattended jobs with an approval workflow. |
| **Shell scripts** | Universal, zero learning curve. No structured results, no policy, no audit, and the hop chain gets pasted into every script. |
| **Chef / Puppet / Salt** | Desired-state at fleet scale, agent-based. A different problem entirely. |
| **This tool** | Steps with declared expectations, automatic failure diagnostics, permission gates, and results an agent can reason about. Small ecosystem — you write the operations. |

**Rule of thumb:** if the answer to "what should this server look like?" is the
question, use Ansible. If the question is "walk through this runbook on that
server and tell me what broke", this fits better.

---

## 5b. Task briefs and preflight

### What it does

A **task brief** is the instruction document for one job: one host, an ordered
list of operations from the catalogue, the conditions that must hold before
starting, what "done" looks like, and the rules the agent must obey.

```yaml
brief:
  id: TB-2026-0812-001
  title: Install monitoring agent 1.4.2 on the QA application server
  host: win-target02
  change_ref: CHG0043211

preflight:
  expect_hostname: WIN-TARGET02
  require_free_disk_gb: 5
  abort_if: [pending_reboot, active_msi_install]

operations:
  - operation: install-package
    params: {package: agent-1.4.2.msi}
    on_failure: stop

success_criteria:
  - The MonitoringAgent service is present and Running

rules:
  reboot_allowed: false
```

`operations.yaml` says what *may ever* be run; a brief says what to do *this
time*. Adding a capability is a reviewed change; using one tonight is a work
order. A brief cannot invent a capability — every operation it names must already
exist and be permitted on that host.

### Validation before anything connects

`ac brief validate` catches, as **errors**: an unknown host, a host with no
usable route, an unknown operation, an operation not permitted on that host, an
undeclared or missing parameter, an unknown `start_at`, a `rollback` mode with no
rollback block, a rebooting operation under `reboot_allowed: false`, and a
misspelled rule. As **warnings**: no `expect_hostname`, no `success_criteria`, no
`change_ref`.

All of it happens with no network and no credentials, so a malformed instruction
fails at 15:00 rather than costing you the 22:00 change window.

### The check that matters most

Four connection checks always run, in this order: session live → chain intact →
target responds → **target identity**.

That last one is the reason this feature exists at all. Every hop past the first
arrives over a *local port forward*, and a port number carries no identity. A
stale tunnel, a reused port, or one transposed digit in an inventory address all
produce a session that works perfectly — against the wrong server. The commands
succeed. Nothing downstream notices.

```
FAIL  target.identity  WRONG HOST: expected 'WIN-TARGET02', connected to 'QA-DB03'
        -> Stop. Nothing further should run. This usually means a stale or reused
           local port forward, or a wrong address in inventory.yaml.
```

Ordering is deliberate too: identity is confirmed before disk space, services or
custom checks. There is no point measuring free space on a machine that turns out
to be the wrong one.

Custom preflight checks must be **read-only** — one that tries to change
something is refused, because preflight verifies state rather than creating it.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **A change ticket + a human** | Universal, and the human catches things no schema can. Slow, and "run the usual steps on app01" means something different to each reader. |
| **A runbook wiki page** | Good for knowledge. Not validated, not executable, and drifts from reality silently. |
| **Ansible playbook per change** | Executable and reviewable. But a playbook conflates *capability* and *intent* — every change edits the thing that defines what is possible, and there is no host-identity gate. |
| **Rundeck job definitions** | Parameterised jobs with RBAC and history. Better if you want a UI and scheduling; heavier, and needs a server. |
| **Telling the agent in chat** | Fastest, and the worst. Nothing is validated, nothing is recorded, "the QA box" is ambiguous, and there is no gate on the wrong host. |
| **This tool** | Validated before the window, human-reviewable, executable, and the host-identity check. But it is one host per brief by design, and the format is specific to this tool. |

### When not to use it

For a single ad-hoc read-only command, `ac exec` is enough — a brief would be
ceremony. Briefs earn their keep when the work is destructive, is happening in a
change window, or is being handed to an agent rather than typed by the person who
planned it.

---

## 5c. Campaigns — one brief, many hosts

### What it does

A **campaign** fans one reviewed brief out across many hosts' *already-live*
sessions, concurrently.

```yaml
campaign:
  id: qa-health-sweep
  title: QA fleet read-only health sweep
  max_parallel: 8
  confirm: false

targets:
  - host: win-target01-dev
    brief: config/briefs/qa-health.yaml
  - host: appwin-qa-vpn          # the same brief, retargeted
    brief: config/briefs/qa-health.yaml
```

```powershell
uv run ac campaign validate config\campaigns\qa-health-sweep.yaml
uv run ac campaign run      config\campaigns\qa-health-sweep.yaml --parallel 4
```

Chain of responsibility: **campaign → brief → operation**. `operations.yaml` is
still the guardrail catalogue at the bottom; a campaign cannot invent a
capability any more than a brief can.

### Two deliberate constraints

**The instruction is central, never on the target.** A campaign references briefs
that live in the repo — reviewed, version-controlled, validated before anything
connects. The target machine is only ever *acted upon*; it never supplies the
agent's instructions. That is what keeps a compromised host from commanding a
privileged, credentialed session.

**Credentials are not handled here.** An operator opens each host's session with
`ac connect <host>` — typing that host's password once — and the campaign
*attaches* to the live sessions by host id. A host with no live session is
reported and **skipped, not connected to**. `ac campaign validate` shows, per
host, whether a session is live.

That is also the honest ceiling on fan-out: a human has to open each session, so
this scales to a handful of hosts, not a fleet of hundreds. Scaling the credential
step (a broker or a vault) is a separate decision this design deliberately has
not made.

### How it works

`plan_campaign` loads and validates every target's brief **offline** — exactly as
`ac brief validate` would — retargeting one brief template to each host. A host
may appear only once per campaign, because a host has one session. Dispatch is a
bounded `ThreadPoolExecutor`; one target's failure is isolated from the rest, and
each returns a structured `TargetResult` (`ok` / `failed` / `skipped` /
`preflight-failed` / `error`).

### Compared to the market

| Approach | Trade-off |
|---|---|
| **Ansible inventory groups** | **Better for scale.** One command against a hundred hosts, with idempotency and forks. But it needs a credential model that works unattended, and no host-identity gate |
| **A `for` loop over `ac run`** | What this replaces. No per-host validation, no concurrency bound, no structured per-target result |
| **Rundeck node filters** | Job-level RBAC, scheduling and a UI. Needs a server |
| **This tool** | Every target's instruction validated offline before anything connects, per-host preflight including the identity gate, and results you can act on per host. Bounded by one human-opened session per host |

---

## 6. Failure diagnosis

### What it does

When a step fails, the material needed to understand *why* is gathered
automatically and returned with the result.

```json
{
  "step_id": "install", "exit_code": 1603, "expectation_met": false,
  "ps_errors": ["Error 1603. Fatal error during installation."],
  "collected_logs": [
    {"source": "C:\\Windows\\Temp\\MSI a1b2c.LOG", "content": "...MSI (s) ... Return value 3."},
    {"source": "eventlog:Application", "content": "..."}
  ],
  "hint": "Generic MSI failure. Search the log for \"Return value 3\".",
  "next_action": "Read collected_logs and hint, fix the cause, then re-run with start_at='install'."
}
```

A glob resolves to the **most recently written** match — which is how you find an
installer log with a generated name like `MSI a1b2c.LOG`.

### Why this division of labour

The engine deliberately does not try to fix anything. It renders, polices, runs,
judges against the declared expectation, and — on failure — gathers what the
operation author nominated. Then it stops and hands everything back.

Deciding what a failure *means* is the agent's job, and it now has the exit code,
the separated error stream, the actual log content and a human-written hint to do
it with. A "clever" engine that guessed at remediation would be wrong in exactly
the situations that matter.

### Compared to the market

Most tools stop at "the command failed, here is stderr". Ansible has excellent
error output for module failures but does not know that a 1603 means *go read the
MSI verbose log and search for Return value 3* — that is domain knowledge the
operation author encodes here, once, for everyone.

Nothing else in this list makes the diagnosis part of the automation contract.
That is the feature this tool is really *for*.

---

## 7. Command safety policy

### What it does

Classifies every command immediately before it is sent, regardless of which layer
asked.

| Tier | Behaviour | Examples |
|---|---|---|
| **BLOCKED** | Refused outright. No confirmation overrides it. | `Format-Volume`, `mkfs`, `dd of=/dev/sda`, `rm -rf /`, `Disable-PSRemoting` |
| **CONFIRM** | Needs explicit confirmation, forcing the agent to ask the operator | `Restart-Computer`, `rm`, `chmod`, `Stop-Service`, `msiexec /x`, `apt install` |
| **ALLOWED** | Runs | `Get-Service`, `df -k`, `tail`, `hostname` |

Whole-line `#` comments are stripped before classification — prose describing
what an exit code means (`# 3010 = installed, needs a reboot`) is not an
instruction, and gating on it would train operators to confirm blindly.

### Honest framing

**This is not a sandbox and does not pretend to be one.** An operator with a
shell can always do more damage than a pattern list anticipates, and a
sufficiently creative command will evade any regex. It exists to stop an agent
from turning a plausible-looking mistake into an outage — which is a real and
common failure mode, and worth a real defence.

Two live bugs found here are instructive about the limits: `rm` was ungated on
Unix while `Remove-Item` was gated on Windows, and `\b/x\b` never matched
` /x ` because the word boundary fails after a space. Pattern lists need testing
like any other code; there are regression tests for both.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **`sudoers` command allow-lists** | **Enforced by the OS** — genuinely stronger. Per-server configuration, and it does not help on Windows. |
| **PAM command filtering** (CyberArk etc.) | Enforced centrally, with recording. Needs the platform. |
| **Nothing** | What most scripts do. |
| **This tool** | Client-side, uniform across SSH and WinRM, zero server configuration. Advisory, not enforced. |

Use `sudoers` *as well*, not instead. This catches the agent's mistakes; the OS
catches everything.

---

## 8. Audit trail and identity

### What it does

Every action is one JSON object, written and `fsync`ed immediately:

```json
{"timestamp": "2026-08-12T09:15:22.431+00:00", "agentId": "AGT-20260812-3f9a1c",
 "sessionId": "SES-3f9a1c", "action": "SSH_CONNECT",
 "source": "JumpServer01", "target": "linux-app01", "result": "SUCCESS"}
```

Sixteen action types cover connect, authenticate, execute, transfer, collect,
block, and terminate. Identity fields use canonical spellings so the trail drops
into a SIEM without a transform step.

**Per-run identity.** `AGT-<date>-<suffix>` per agent instance, `SES-<suffix>`
per session, with a random suffix so concurrent runs on one machine never share
an id. A single static id makes concurrent executions indistinguishable — which
is precisely when telling them apart matters. Name a run explicitly with
`ac connect --agent-id` or `AC_AGENT_ID`.

**Execution timeline.** `ac timeline <session>`:

```
13:54:30  SESSION_START        local -> aix-via-hop  local -> aix-target01 (ssh) -> aix-via-hop (ssh)
13:54:31  SSH_CONNECT          local -> aix-target01  10.0.0.36:22 (0.81s)
13:54:32  SSH_CONNECT          aix-target01 -> aix-via-hop  10.0.0.36:22 (0.8s)
13:54:41  SCRIPT_EXECUTE       local -> aix-via-hop  linux-health/snapshot (0.19s)
13:54:42  COMMAND_EXECUTE      local -> aix-via-hop  df -k | head -3 (0.3s)
13:54:43  COMMAND_BLOCKED      local -> aix-via-hop  rm /tmp/nope
13:54:44  SESSION_END          local -> aix-via-hop  closed
```

Configurable location, level and retention, with automatic pruning.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **Teleport session recording** | **Substantially better**: replayable terminal video, tamper-evident, centrally stored, per-user RBAC. Needs the infrastructure. |
| **CyberArk PSM** | Full session video, keystroke logs, compliance reporting. Needs the platform. |
| **`script(1)` / terminal logging** | Captures everything a human saw. Unstructured — you cannot query "every command run on host X last week". |
| **Ansible logs / callback plugins** | Good task-level records. Not designed as a security audit trail. |
| **This tool** | Structured, queryable, SIEM-ready, zero infrastructure, and it records *intent* (operation, step, expectation, refusal) not just bytes. But it is **written by the thing being audited** — a compromised client writes whatever it likes. |

**That caveat is important.** For genuine tamper-evidence you need the recording
to happen somewhere the operator does not control, which means a proxy or PAM
product. This trail is excellent for "what did the agent do and why did it fail";
it is not a chain-of-custody artefact.

---

## 9. Session daemon

### What it does

Holds the authenticated chain open in a process so a twenty-step run does not
re-authenticate twenty times.

`ac connect` runs in the operator's terminal — the only place a prompt can appear
— then serves that session on a loopback socket. `ac run` and `ac exec` attach by
host id and never see a credential.

### Why it exists

Directly downstream of the credential decision. Prompting per command would make
a patch run unusable, and Windows OpenSSH has **no `ControlMaster`**, so
multiplexing must happen in-process.

### Security boundary, stated plainly

The socket binds to `127.0.0.1` only and every request carries a random 256-bit
token from a `0600` descriptor file. **This is a convenience boundary, not a
privilege one.** Any process running as the same user can read that file and
drive the session — the same trust level as an `ssh-agent` socket. It protects
against other users on the box and against the network; it does not protect
against malware running as you.

### Compared to the market

| Approach | Trade-off |
|---|---|
| **`ssh` ControlMaster** | The standard answer on Unix, kernel-mediated socket, zero code. **Does not exist on Windows OpenSSH.** |
| **`tmux` / screen** | Keep a shell alive and reuse it. Fine for humans, awkward to drive programmatically. |
| **Re-authenticating each time** | Simple and stateless. Unusable when each connection costs three typed passwords. |
| **This tool** | Works on Windows, correct teardown, agent-drivable. Costs a terminal window that must stay open. |

### Reloading without reconnecting

Editing an operation would otherwise mean reconnecting, and reconnecting costs a
password at every hop — which makes iterating on a runbook painful enough that
people stop doing it.

```powershell
uv run ac reload <host>     # re-reads operations.yaml into the live session
```

It reports what was added and removed. Only the *catalogue* is reloaded; the
inventory is re-read solely to check the route has not changed underneath the
live connection. If it has, the reload is **refused** — the honest answer there
is to reconnect.

---

## 9b. The operator prompt and hop fallback

### What it does

The `ac connect` window is not a dead window that says "leave this open". It is a
prompt on the machine you are connected to, and it always names that machine:

```
appuser@10.0.0.29 [app-stg01-bastion] $
operator@bastion-staging.example.net [bastion-staging · FALLBACK] $
```

`:help`, `:status`, `:where`, `:route`, `:retry`, `:timeout <secs>`, `:exit`.
Anything else runs on that machine through the same audited channel with the same
deny-list — `CONFIRM` is satisfied because a human typed it, but `BLOCKED` still
holds. `cd` is remembered between commands on POSIX hosts; nothing else is,
because each command opens its own channel.

### Why it exists

Before it, an operator who wanted to *look* at the machine opened a second
connection and typed every password again. The window was authenticated and idle.

### Hop fallback — the part that saves a change window

If the bastion chain stands up but the **target leg fails**, the session is not
thrown away. It is held at the last node that did authenticate — the Windows jump
server if PSRP got that far, otherwise the last SSH hop — which is precisely the
machine that was supposed to reach the target, and therefore where the useful
diagnosis lives.

```
fallback -- held at bastion-staging
  The leg to axwayApp01-cvt failed:
      Authentication failed for 'axway'
  The chain up to bastion-staging did authenticate, so the session is being held
  there rather than thrown away.
  Diagnose from that machine, then run :retry. The hops stay authenticated, so a
  retry costs no password.
```

While degraded the tool is loud and restrictive about it: the prompt is marked
`· FALLBACK`, **every catalogue operation is withdrawn**, and `ac exec` is
refused — because an agent that believes it is on the application server and is
actually on the bastion is exactly the failure this whole tool exists to prevent.
`session.degraded` and `session.recovered` bracket the period in the audit trail.

`--no-fallback` disables it, and a one-shot `EphemeralSession` (used by `ac rdp`
/ `ac shell` / `ac tunnel`) never falls back at all: a command that silently ran
somewhere other than where it was aimed would be a lie.

### Compared to the market

Nothing else in this list does it, because nothing else in this list *owns* the
chain: `ssh -J` either connects or does not. The nearest equivalent is a human
noticing the failure, opening a shell to the bastion by hand, and retyping two
passwords.

**Not a replacement for `ac shell`.** That hands you the system `ssh` client and
a real TTY, which is what you want for anything full-screen. The prompt is for
the checks you run *while* holding a session.

---

## 10. Interactive handoff

`ac rdp <node>` forwards 3389 through the chain and launches `mstsc`.
`ac shell <node>` opens an interactive SSH shell. `ac tunnel <node>` gives you the
forward for any other client.

**Credentials default to *not* being staged** — `mstsc` prompts, which is exactly
the manual-entry model. Staging via `cmdkey` is opt-in, because it puts the
password on a command line for a few milliseconds, and the stored credential is
always removed afterwards including on interruption.

The system `ssh` client is used rather than a Paramiko shell loop: it already
handles terminal raw mode, window resizing and Ctrl-C correctly on Windows, and
reimplementing that badly would be worse than shelling out.

**Compared to mRemoteNG:** mRemoteNG is better at this. It is a mature connection
manager with a saved tree, tabs, and one-click access. This is not trying to
replace it — `ac rdp` exists so the *automation* has an escape hatch to a human,
and `preestablished` exists so mRemoteNG's tunnels can be reused.

---

## 11. The CLI

### The CLI is the only interface

Every command takes `--json`, so an agent drives the whole tool through a shell
and gets steps, collected logs and hints back as structured data rather than
terminal text to scrape. One entry point, one permission surface
(`Bash(uv run ac ...)`), nothing to keep in step with the core.

The workflow rules an agent must follow — preview before approval, relay the
summary, never ask for a password in chat — live in
[instructions-guide.md](instructions-guide.md).

---

## 12. Secret redaction

Every string leaving the process — console output, audit records, exception
messages — passes through a scrubber. `ExecResult` scrubs itself on
construction, so a password echoed by a remote command cannot reach a log even if
nobody remembered to filter it at the call site. `RedactingError` scrubs its own
message, so a traceback cannot leak a credential embedded in a connection string.

Verified by test: the end-to-end audit trail on disk contains neither the bastion
nor the target password.

Most tools rely on never putting the secret in the string in the first place.
That works until someone writes a debug line.

---

## Head-to-head

| | This tool | plink + script | Ansible | mRemoteNG | Teleport | CyberArk PAM |
|---|---|---|---|---|---|---|
| Install on targets | none | none | none (Python for modules) | none | agent or proxy | connector |
| Validated work order | **✓** | ✗ | partial | ✗ | ✗ | approval workflow |
| Wrong-host guard | **✓** | ✗ | ✗ | ✗ | n/a (cert-bound) | n/a (brokered) |
| Infrastructure needed | none | none | none | none | proxy cluster | vault + PSM |
| Multi-hop chains | declared, validated | manual | `ProxyJump` string | saved tunnels | native | native |
| Windows automation | WinRM/PSRP | ✗ | WinRM | ✗ | limited | via connector |
| Credentials at rest | **none** | on command line | vault file | encrypted file | certificates | central vault |
| Per-hop prompting | ✓ | ✗ | ✗ | ✗ | ✗ (certs) | brokered |
| MFA passthrough | ✓ | ✓ | limited | ✓ | ✓ | ✓ |
| Idempotent | ✗ | ✗ | **✓** | ✗ | n/a | n/a |
| Structured results | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ |
| Automatic failure diagnosis | **✓** | ✗ | partial | ✗ | ✗ | ✗ |
| Command policy | advisory | ✗ | ✗ | ✗ | RBAC | **enforced** |
| Audit trail | structured JSON | ✗ | task logs | ✗ | **recorded** | **recorded** |
| Tamper-evident audit | ✗ | ✗ | ✗ | ✗ | **✓** | **✓** |
| Unattended / scheduled | ✗ | ✓ | **✓** | ✗ | ✓ | ✓ |
| Agent-friendly output | **✓** | ✗ | partial | ✗ | ✗ | ✗ |
| Cost | free | free | free/paid | free | paid | paid |
| Time to first use | minutes | minutes | hours | minutes | weeks | months |

---

## When to use something else

Say this plainly, because picking the wrong tool wastes more time than any
feature saves.

**Use Ansible instead when** the question is "what should this server look like".
Idempotency, thousands of maintained modules, and a community that has solved
your problem already. If you find yourself writing operations that check whether
something is already done, you want Ansible.

**Use Teleport or a PAM product instead when** you need *enforced* access control,
tamper-evident session recording, per-user RBAC, or a compliance auditor to sign
something off. This tool's route graph and audit trail are correctness features,
not security controls.

**Use plink or OpenSSH directly when** you need one command through a bastion, or
a tunnel for an unrelated tool, on a machine where installing Python is not worth
it. That case is explicitly supported via `preestablished`.

**Use mRemoteNG when** a human wants a desktop. It is better at that.

**Use Rundeck or AWX when** you need scheduled, unattended, approval-gated jobs
with a web UI and history.

**Use this tool when** an agent or an operator needs to walk a runbook across a
chain of bastion and jump hosts, on a mix of Unix and Windows, with credentials
typed by a human, nothing installed on the targets, and a structured account of
what happened — especially when the interesting part is diagnosing what broke.

---

## Honest limitations

Known, and none of them hidden elsewhere in the docs.

1. **Not idempotent.** Running an operation twice runs it twice. This is
   procedural automation, like a human runbook.
2. **An operator must be present.** No unattended scheduled runs — a direct
   consequence of never storing credentials.
3. **The terminal must stay open** for the life of the session, same reason.
4. **One Windows jump server maximum.** Each Windows-to-Windows leg is an
   `Invoke-Command` run by the hop before it; nesting deeper means passing a
   credential through an intermediate script.
5. **WinRM double-hop.** A remote session cannot forward your credentials onward,
   so a target cannot reach a UNC share on its own behalf. Mitigated by assuming
   a server-local package share; otherwise needs CredSSP or upload-then-install.
6. **The route graph is advisory.** It constrains this tool, not the network.
7. **The audit trail is written by the audited process.** Not tamper-evident.
8. **The command policy is a pattern list.** It will not catch everything.
9. **`.ppk` keys need conversion** — Paramiko cannot read PuTTY's format.
10. **No RBAC, no SSO, no multi-user approval workflow.** One operator, one
    session. `--confirm` is a flag the caller passes; nothing proves a human
    approved at that moment.
11. **`ac exec` is not covered by `--ops`.** The session allow-list scopes
    *catalogue operations*; ad-hoc commands are gated only by the deny-list.
12. **Small ecosystem.** The operations are the ones you write.
13. **The nested Windows-to-Windows leg is unproven against real hardware.**
    Direct WinRM (`via: {from: local}`) has been verified end to end against a
    live Windows Server 2022 host, and the SSH path against production AIX
    through a real bastion chain. The bastion → Windows jump → Windows target
    shape is implemented and unit-tested but has not run against live hardware.
    See [STATUS.md](../../STATUS.md).
14. **Campaign fan-out is bounded by human-opened sessions.** No credential
    broker, so hosts without a live session are skipped.

---

## Further reading

| Guide | Contents |
|---|---|
| [ARCHITECTURE.md](../ARCHITECTURE.md) | Components, data flows, auth and authz paths, trust zones |
| [SECURITY.md](../SECURITY.md) | Threat model, controls, hardening, incident response |
| [CONFIGURATION.md](../CONFIGURATION.md) | Every setting and environment variable |
| [OPERATIONS.md](../OPERATIONS.md) | Running it in dev and production, monitoring, upgrades |
| [implementation/](../implementation/README.md) | Module contracts, CLI reference, audit events, wire protocol |
| [instructions-guide.md](instructions-guide.md) | The task brief format and the rules for instructing the agent |
| [operations-guide.md](operations-guide.md) | Adding a host or an operation |
| [testing.md](testing.md) | Test strategy, the two end-to-end loops |
| [runbook.md](runbook.md) | Running it step by step, then troubleshooting by symptom |
