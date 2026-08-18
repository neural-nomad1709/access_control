# Runbook

**Part 1 — [Running it, step by step](#part-1--running-it-step-by-step).** Start
here if you have never used the tool.
**Part 2 — [Troubleshooting by symptom](#part-2--troubleshooting-by-symptom).**
Symptoms in the order you are likely to hit them.

---

# Part 1 — Running it, step by step

## The mental model, first

Three ideas explain every command:

1. **A session is a thing you hold open.** `ac connect` opens one in *your*
   terminal and prompts for a password at every hop. Nothing is stored — the
   credentials live in that process and are wiped when it exits. Every other
   command (`ac run`, `ac exec`, and Claude) *attaches* to that session by host
   id and never sees a credential.
2. **Nothing is discovered.** If a machine is not in `inventory.yaml` with a
   `via:` block, it cannot be reached. There is no fallback to a direct
   connection.
3. **Three files, three lifetimes.** `inventory.yaml` = where machines are and
   who you log in as. `operations.yaml` = what may *ever* be run. A **task
   brief** = what to do *this time*. You will edit the first once per estate
   change, the second rarely, and write a brief per job.

You will normally have **two terminals**: one holding `ac connect`, one running
everything else.

---

## Step 0 — Check the machine you are sitting at

```powershell
uv run ac doctor
```

Verifies config parses, dependencies exist, every `key_file` is present and
readable, and that you have an interactive terminal for password prompts. It ends
with `Ready.` or tells you what is missing. **Nothing here touches the network.**

## Step 1 — Describe the machines you need to reach

Edit `config/inventory.yaml`. One block per machine: who it is, and a `via:`
saying how it is reached and from where. See
[operations-guide.md](operations-guide.md#declaring-how-to-reach-it) for the full
field list.

## Step 2 — Read the map, before connecting to anything

```powershell
uv run ac routes                  # every declared leg, and your entry points
uv run ac routes win-target02       # resolve one route, with context per hop
uv run ac hosts                   # every target and whether its route resolves
```

These connect to nothing. If a route is wrong, it is wrong *here*, for free —
not at 22:05 in a change window. `ac routes <host>` prints the execution shape
(`ssh`, `winrm`, `nested-winrm`), which is how the commands will actually be
carried.

## Step 3 — Find out what actually answers

```powershell
uv run ac probe win-target02 --deep
```

The first command that uses the network. It prompts for the bastion credentials,
then reports what each machine on the way answers on — and critically, whether
the bastion permits **TCP forwarding**, which is the mechanism every hop is built
on. `--deep` also asks the Windows jump server whether *it* can reach the target,
which is the only way to test the last leg.

Run this whenever an address changes. It is read-only.

## Step 4 — Open a session (your terminal, one per host)

```powershell
uv run ac connect win-target02
```

Prompts per hop: bastion, jump server, target. **Leave this window open** — it
becomes a prompt on the host:

```
corp\svc_deploy@win-app01.corp.net [win-target02] >
```

The prompt always names the machine the next command reaches, and anything you
type runs there through the same audited channel. `:help` lists its own commands
(`:status`, `:where`, `:route`, `:retry`, `:timeout <secs>`, `:exit`). `cd` is
remembered between commands on POSIX hosts; nothing else is, because each command
opens its own channel.

Options worth knowing:

```powershell
uv run ac connect win-target02 --ops install-package,windows-health
uv run ac connect win-target02 --idle-timeout 7200      # 0 = never expire
uv run ac connect win-target02 --no-shell               # hold it open with no prompt
uv run ac connect win-target02 --no-fallback            # fail rather than hold at a hop
```

`--ops` restricts the session to those operations. Belt and braces: the session
then refuses anything else even if `operations.yaml` is edited underneath it.
Default idle timeout is 30 minutes; when it expires the credentials are wiped and
you reconnect.

**If the last leg fails**, the session is not thrown away. It is held at the last
hop that did authenticate — marked `· FALLBACK` in the prompt — so you can
diagnose from the machine that was supposed to reach the target, then type
`:retry`. The hops stay authenticated, so a retry costs no password. While it is
a fallback, operations and `ac exec` are refused, because commands there would
run on the hop rather than on the target.

## Step 5 — Prove you are on the machine you think

```powershell
uv run ac verify win-target02 --expect-hostname WIN-TARGET02
```

**Do not skip this.** Every hop past the first arrives over a local port forward,
and a port number carries no identity. A stale forward, a reused port, or one
transposed digit in an address produces a session that works perfectly — against
the wrong server. This asks the machine its own name and compares it:

```
  ok  session.live      session open, expires in 600s of inactivity
  ok  chain.intact      2 SSH hop(s) active
  ok  target.responds   round trip 0.16s
FAIL  target.identity   WRONG HOST: expected 'WIN-TARGET02', connected to 'QA-DB03'
```

## Step 6 — Look before you touch

```powershell
uv run ac ops                                        # what may be run at all
uv run ac preview win-target02 install-package -p package_share='D:\packages' -p package=agent-1.4.2.msi
```

`ac preview` renders the exact commands with every `{{placeholder}}` filled in,
and **connects to nothing**. Approving `Install {{package}}` is not informed
consent; approving the rendered command is.

## Step 7 — Do the work

**One operation, interactively:**

```powershell
uv run ac run win-target02 windows-health
uv run ac run win-target02 install-package -p package_share='D:\packages' -p package=agent-1.4.2.msi --confirm
```

`--confirm` approves a gated (destructive) operation — without it you are asked.
`--dry-run` renders and runs nothing. `--start-at <step>` resumes a partly-done
operation instead of repeating work; `--only <steps>` runs a subset.

**A whole job, from a brief** — this is the real workflow for a change window:

```powershell
uv run ac brief validate config\briefs\my-brief.yaml   # no network; do this early
uv run ac brief show     config\briefs\my-brief.yaml   # a human reads and approves
uv run ac brief run      config\briefs\my-brief.yaml --confirm
```

Steps 1–2 need no network and no credentials. Do them **before** the window. A
brief that fails validation at 22:05 costs you the window; the same failure at
15:00 costs you a minute. Start from `config/briefs/TEMPLATE.yaml` and see
[instructions-guide.md](instructions-guide.md).

**The same job across several hosts** — a campaign, dispatched to sessions that
already exist:

```powershell
uv run ac connect host-a          # one terminal each, opened by a human
uv run ac connect host-b

uv run ac campaign validate config\campaigns\qa-health-sweep.yaml   # offline
uv run ac campaign run      config\campaigns\qa-health-sweep.yaml --parallel 4
```

Hosts without a live session are reported and skipped, never connected to —
campaigns handle no credentials.

**Ad hoc, when diagnosing:**

```powershell
uv run ac exec win-target02 -- 'Get-ChildItem D:\'
uv run ac logs win-target02 --path 'C:\Windows\Temp\*.log' --tail 200
uv run ac upload win-target02 .\patch.msu 'D:\packages\patch.msu'
```

Note the `--` before an `exec` command. Anything you do more than once belongs in
`operations.yaml`, where it gets expectations, failure diagnostics and review.

**When something genuinely needs a GUI:**

```powershell
uv run ac rdp JumpServer01      # a hop or a host
uv run ac shell bastion1          # interactive SSH through the chain
uv run ac tunnel win-target02       # hold a forward open for any other client
```

`ac rdp` is also how you bootstrap a host with WinRM switched off — log in once
and run `Enable-PSRemoting -Force`.

## Step 8 — Read what happened

```powershell
uv run ac timeline <session-id>   # what ran, in order, with timings
uv run ac audit                   # recent sessions
uv run ac audit <session-id>      # every record in one session
```

`ac timeline` is the fastest first look after a failure. Trails live in
`%LOCALAPPDATA%\access_control\logs\` and contain no secrets — grep them freely.

## Step 9 — Close it

```powershell
uv run ac disconnect win-target02
```

Prints the final status first. Credentials are wiped either way; the audit trail
stays on disk.

---

## The short version

```powershell
uv run ac doctor                                  # once, on your machine
uv run ac routes <host>                           # is the path declared?
uv run ac probe <host> --deep                     # does it actually answer?
uv run ac connect <host>                          # your terminal; leave it open
uv run ac verify <host> --expect-hostname <NAME>  # right machine?
uv run ac preview <host> <operation> -p k=v       # what exactly will run?
uv run ac run <host> <operation> -p k=v --confirm # do it
uv run ac timeline <session-id>                   # what happened
uv run ac disconnect <host>
```

## Two rules that will save you

- **Never type a password into a chat.** If Claude says there is no live session,
  it is asking *you* to run `ac connect` in your own terminal — not asking for
  your password.
- **A running session holds the catalogue it started with.** Edited
  `operations.yaml`? `ac reload <host>` — it re-reads the catalogue without
  costing a password, and reports what was added and removed. It is refused if
  the host's *route* changed, because the live connection would no longer match
  the config; that case needs a reconnect. Edited the tool's own source?
  Reconnect. A fix that appears not to work is usually just not loaded yet.

---

# Part 2 — Troubleshooting by symptom

## "no live session for '<host>'"

Expected, not a bug. Credentials are never stored, so a session has to be opened
by a human:

```powershell
! uv run ac connect <host>
! uv run ac shell bastion1
```

Leave that window open. `ac run`, `ac exec` and Claude all attach to it by host
id.

If Claude reports this, it is asking you to run that command — **not** asking for
your password. Never type a password into the chat; it would be recorded in the
conversation.

---

## WinRM is closed on the jump server or target

`ac probe <host>` shows `winrm-http: False` and a `bootstrap-needed` verdict.

This is the common case in a locked-down estate, and the design has a route
through it. RDP in once, by hand, and turn PowerShell Remoting on:

```powershell
uv run ac rdp JumpServer01
```

Then in that desktop session, as an administrator:

```powershell
Enable-PSRemoting -Force
# If the target is not on the same domain, or you connect by IP:
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
# Confirm it answers:
Test-WSMan -ComputerName localhost
```

Close the RDP session and re-probe. From then on the host is fully automated —
this is a one-time bootstrap per machine.

If group policy forbids WinRM entirely, the alternatives are, in order of
preference:

1. **Windows OpenSSH Server** — set `automation: ssh` for that host. Install with
   `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`.
2. **WMI/DCOM (135)** from the previous hop, used only to enable WinRM.
3. **Interactive RDP** — the agent tells you what needs doing and hands you the
   session.

---

## "ERROR: No route defined between requested target and available bastion"

Not a network problem. Nothing was attempted — the target has no declared edge
reaching it, and the tool will not invent one or fall back to a direct
connection.

```powershell
uv run ac routes            # what is declared
uv run ac routes <host>     # resolve one route
```

Give the machine a `via:` block in `inventory.yaml`, naming the address **as seen
from `from:`** and an explicit port:

```yaml
  linux-app01:
    kind: linux
    username: appuser
    via:
      from: JumpServer01
      hostname: linux-app01.corp.net
      port: 22
      protocol: ssh
```

Related refusals, all raised when the config is read:

| Message | Fix |
| --- | --- |
| `no chain of edges connects it back to 'local'` | The node is declared but nothing links it to an entry point. Give some node on the chain a `via: {from: local, ...}`. |
| `has a source '<id>' that is not defined under 'hops:' or 'hosts:'` | A `via.from` (or a `routes:` entry) names a machine that is commented out or misspelled. |
| `connectivity is declared twice` | The file has both `via:` blocks and a top-level `routes:` list. Keep one — `via:` is preferred. |
| `ambiguous route: N declared paths of equal length` | Two ways in. Remove one edge, or split the target per environment. |
| `crosses an environment boundary: QA -> PROD` | Environments are separated deliberately. If the traversal is genuinely intended, align the `context.environment` values or declare a dedicated node. |
| `port: required` | Ports are mandatory on every edge. The message names what the default would have been. |
| `cannot run commands` | RDP was declared under `automation`. It has no exit code; move it to `interactive`. |
| `rdp-only, but a route passes through it` | An intermediate hop must run commands so the next leg can launch from it. Give it an `automation` endpoint. |

---

## "cannot reach localhost:44001" on a pre-established hop

That edge is declared `preestablished: true`, meaning something else is expected
to be listening on that local port already. Start the tunnel:

```powershell
ssh -p 2222 -L 44001:jumpserver:3389 -L 45985:jumpserver:5985 operator@bastion1.example.net
```

Alternatively, remove `preestablished` and give the jump server's **real** address
as seen from the bastion — then this tool builds the forward itself, which is
usually simpler:

```yaml
  JumpServer01:
    username: jumpuser
    domain: corp
    via:
      from: bastion1
      automation:  {hostname: 10.20.4.11, port: 5985, protocol: winrm}
      interactive: {hostname: 10.20.4.11, port: 3389, protocol: rdp}
```

A loopback address always implies `preestablished`, because treating `localhost`
as a real host would connect to your own machine.

---

## "tcp forwarding: NO" / "cannot open a forward to <host>:<port>"

The single most important failure in a segmented environment, and the one most
often misdiagnosed.

`ac probe` now answers it directly, per bastion:

```
  bastion1         bastion  bastion1.example.net:2222   open: ssh
      tcp forwarding: yes
```

**If it says `NO`**, the bastion refused the forwarding channel outright
(`SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`). Its sshd config has
`AllowTcpForwarding no`, or a `Match` block disables it for your user. Every jump
through that host is impossible until it changes, and **there is no client-side
workaround** — forwarding is the mechanism hopping is built on. This needs whoever
owns the bastion, not a config change here.

Do not confuse it with an unreachable destination. If forwarding is permitted but
the target does not answer, the probe reports the port as closed instead, and the
problem is a firewall between bastion and target. Confirm from the bastion:

```powershell
uv run ac shell bastion1
# then, on the bastion:
nc -vz 10.20.4.11 5985      # or:  timeout 3 bash -c '</dev/tcp/10.20.4.11/5985'
```

### If forwarding is blocked but you still need through

The remaining options, in order of preference:

1. **Get `AllowTcpForwarding yes`** for your user, scoped by a `Match` block if
   the bastion owner wants it narrow.
2. **Use a forward someone else is permitted to create** — mRemoteNG's own SSH
   tunnel entry, or a jump-host appliance — and declare it `preestablished` so
   this tool dials it rather than building one.
3. **Interactive only.** `ac rdp` still works if the tunnel comes from elsewhere;
   automation does not.

---

## "HOST KEY MISMATCH"

Nothing was sent. The key offered by the server does not match the one recorded
in `known_hosts`.

This means either the server was legitimately rebuilt, or the connection is being
intercepted. Do not "fix" it by deleting the line until you know which.

1. Confirm with whoever owns the server that its host key changed.
2. Only then remove the stale entry:

```powershell
ssh-keygen -R "[bastion1.example.net]:2222"
```

Unknown-on-first-contact is different and is accepted by default (OpenSSH's own
behaviour), with the fingerprint recorded in the audit trail. To require every
key to be known in advance:

```powershell
$env:AC_HOST_KEY_POLICY = "strict"
```

---

## "is a PuTTY .ppk key"

Paramiko cannot read PuTTY's format. Convert once:

```powershell
puttygen "C:\path\to\key.ppk" -O private-openssh -o "C:\path\to\key.pem"
```

Then point `key_file` at the `.pem`. If PuTTYgen is not installed, it ships with
PuTTY, or use `winget install PuTTY.PuTTY`.

---

## Authentication fails on the bastion

**Look at the username on the prompt before you doubt the password.**

```
== QA and Dev SSH bastion [QA] [prod\operator@bastion1.example.net:2222] ==
   user: prod\operator
error: password authentication failed.
```

Setting `domain:` on a node qualifies its login to `DOMAIN\user` — on **every**
kind, not just Windows. Unix hosts joined to AD through SSSD, winbind or Centrify
accept that form over SSH like any other login name.

So the question is what your server expects, and the two answers look identical
when wrong — both give "password authentication failed", which reads as a bad
password and sends people resetting a credential that was fine.

| Server | Wants | Config |
| --- | --- | --- |
| Plain OpenSSH, local accounts | `operator` | omit `domain:` |
| AD-integrated (SSSD/winbind/Centrify) | `prod\operator` | `username: operator` + `domain: prod` |

`~/.ssh/config` is the fastest evidence: whatever `User` you already log in with
by hand is what this tool should send.

**A username that contradicts its `domain:` is refused** when the config is read.
This is the silent case worth understanding: a username already carrying a domain
is left as-is, so a disagreeing `domain:` was simply discarded and you
authenticated as an identity the file never stated.

```
hosts.app: username 'prod\operator' already carries the domain 'prod', but
domain: 'corp' says otherwise. The login would use 'prod' and 'corp' would
be silently ignored.
```

Either drop `domain:` and keep the qualified username, or use the bare name and
let `domain:` qualify it. Don't write both.

Check what will actually be sent, for every node, without connecting:

```powershell
uv run ac hosts
uv run ac routes            # the domain column is taken from the node itself
```

The password is never kept after a rejection, so you are simply prompted again on
retry. Other things to check:

- **Is the auth method right?** `ac doctor` shows what each hop is configured
  for. A server with `AuthenticationMethods publickey,password` needs
  `method: key+password`; `password` alone will fail after the key stage.
- **Is it the right key?** `ac doctor` verifies each `key_file` exists and is
  readable OpenSSH format.
- **Is an OTP being asked for?** A keyboard-interactive challenge is shown to you
  verbatim. If you see the server's own prompt text, answer that, not your
  password.

---

## "this session is held at '<hop>' because the leg to '<host>' failed"

Not a bug — the fallback doing its job. The bastion chain authenticated, the last
leg did not, and the session is being held at the hop rather than thrown away.

Operations and `ac exec` are refused there on purpose: they are written against
the target, and running them on a bastion would be worse than failing.

Go to the `ac connect` window (the prompt shows `· FALLBACK`) and diagnose from
that machine — it is the one that was supposed to reach the target:

```
:where                    # what failed, and why
nc -vz 10.20.4.11 5985    # can this hop reach the target at all?
:retry                    # re-attempt the leg — costs no password
```

If the far end needs fixing first, fix it and `:retry` again; the hops below stay
authenticated for as long as the window is open. `ac connect --no-fallback` turns
the behaviour off if you would rather fail outright.

---

## WinRM fails with SEC_E_LOGON_DENIED / `0x8009030C` on a direct route

**This is not a wrong password**, and the credential is almost certainly fine.

On a workstation whose Group Policy sets *Restrict NTLM: Outgoing NTLM traffic =
Deny*, with an allow-list that has no entry for the target, Windows SSPI refuses
to emit the NTLM token **locally**, before a single packet is sent. The failure
surfaces as an authentication error, which sends people resetting credentials
that were never the problem.

Two ways through:

1. **Use the bastion path** (the compliant one). NTLM then originates to
   `127.0.0.1` through the tunnel, which the policy does not block.
2. **Let `ntlm_provider: auto` do its job.** For a direct route
   (`via: {from: local}`) it already selects the pure-Python NTLM provider, which
   does not consult the LSA allow-list. Confirm which was used:

```powershell
uv run ac audit <session-id> --json    # look for event "winrm.ntlm_provider"
```

Forcing it: `auth.ntlm_provider: python` on the host, or `AC_WINRM_PYTHON_NTLM=1`
in the environment. Understand that this deliberately steps around a corporate
control — see [../SECURITY.md](../SECURITY.md#35-ntlm-provider-selection) before
making it a habit.

---

## WinRM returns an empty "Bad HTTP response ... Code: 400"

A wedged transport, usually a desynced NTLM message-seal after the pure-Python
provider has been running for a while. The tool recovers from it automatically:
it rebuilds the whole pypsrp client (a fresh handshake, reusing the stored
credential — no re-prompt) and re-runs the same script once. That is safe because
the request was rejected before the shell executed it.

If you see it repeatedly, the usual root cause is a **malformed command**, and on
Windows the usual root cause of *that* is quoting:

```powershell
uv run ac exec <host> -- '$env:COMPUTERNAME'    # correct: single quotes
uv run ac exec <host> -- "$env:COMPUTERNAME"    # wrong: your LOCAL shell expands it
```

---

## WinRM returns 401 / "credentials were rejected"

Almost always the username *form*. WinRM wants one of:

```
corp\jumpuser
jumpuser@corp.example.com
```

A bare `jumpuser` will fail against a domain-joined host — and the failure presents
as a wrong *password*, which sends people resetting credentials that were fine.

Set `domain:` on the node and the tool qualifies it for you:

```yaml
  JumpServer01:
    username: jumpuser
    domain: corp        # authenticates as corp\jumpuser
```

`ac routes` shows the domain on each edge, and the password prompt shows the
qualified identity, so you can confirm what will actually be sent.

If the form is right and it still fails, the account may lack Remote Management
rights. Check membership of **Remote Management Users**, or run as an
administrator.

---

## The nested leg fails: "cannot reach <target> from <jump>"

The jump server itself cannot get to the target. Confirm from a desktop session
on the jump server:

```powershell
Test-NetConnection 10.0.0.141 -Port 5985
```

- `TcpTestSucceeded: False` → firewall between them, or WinRM is off on the
  target. Bootstrap the target as above.
- `True` but authentication fails → the credential for the *target* is wrong, or
  the target does not trust the jump server for Negotiate auth. Add the target to
  the jump server's `TrustedHosts`.

---

## An installer needs a file on a UNC share ("double-hop")

A WinRM session cannot forward your credentials onward, so the target cannot
authenticate to a file server on its own behalf. Accessing `\\fileserver\share`
from inside a remote session fails with access denied even though it works when
you RDP in.

Options, best first:

1. **Use a server-local share.** The shipped `install-package` operation takes
   `package_share` as a required parameter and assumes it is a local path such as
   `D:\packages`, supplied by the brief. This sidesteps the problem completely
   and is why the design recommends it.
2. **Copy first, then install** — `upload_file` to the target, then run the
   installer against the local copy.
3. **CredSSP** — set `auth.transport: credssp` for the host. This delegates your
   credentials to the target, which is exactly the risk it sounds like. Only with
   the security team's agreement.

---

## MSI exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Success | — |
| 1603 | Generic failure | Read the verbose log; search for `Return value 3` |
| 1618 | Another install in progress | `Get-Process msiexec`, wait, retry |
| 1619 | Package could not be opened | Corrupt or truncated file on the share |
| 1620 | Not a valid installer | Wrong file |
| 3010 | Success, reboot required | **Do not re-run.** Ask the operator to schedule a reboot |
| 1638 | Another version already installed | Uninstall first, or use a patch |

The shipped `install-package` operation already collects the verbose log and
attaches the matching hint for each of these.

---

## A step times out

`timed_out: true` and a null exit code. The pipeline was stopped, but **the
remote process may still be running** — an MSI does not stop because we stopped
watching.

```powershell
uv run ac exec <host> -- 'Get-Process msiexec, setup -ErrorAction SilentlyContinue'
```

Raise `timeout_s` on the step if the operation is legitimately slow. Installers
and patch runs need 1800–5400.

---

## The session expired

Default idle timeout is 30 minutes. Credentials are wiped; there is nothing to
recover. Reconnect:

```powershell
uv run ac connect <host> --idle-timeout 7200   # or 0 for no timeout
```

The audit trail from the expired session is complete and still on disk.

---

## Output looks mangled — brackets are missing

If you see `$(::Round(...))` where you expected `$([math]::Round(...))`, something
printed remote text through Rich's markup parser. Report it: every remote string
and every command body must go through `cli._raw` (which sets `markup=False`).
There is a regression test for the preview path.

---

## Nothing works and you want to see why

```powershell
uv run ac doctor                    # config, deps, keys, prompting
uv run ac routes                    # what connectivity is declared
uv run ac routes <host>             # resolve one route, with context per hop
uv run ac hosts                     # do routes resolve?
uv run ac probe <host> --deep       # what actually answers?
uv run ac audit                     # recent sessions
uv run ac timeline <session_id>     # how far it got, and where it slowed down
uv run ac audit <session_id>        # every record in one session
```

`ac timeline` is usually the fastest first look after a failure:

```
12:49:07  SSH_CONNECT           local -> bastion1  bastion1.example.net:2222 (1.2s)
12:49:09  SSH_CONNECT           bastion1 -> app01  10.0.0.36:22 (0.4s)
12:49:12  COMMAND_EXECUTE       local -> app01  df -h (0.3s)
```

Audit trails are at `%LOCALAPPDATA%\access_control\logs\`. They contain no
secrets — grep them freely.
