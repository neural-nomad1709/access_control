# Security

The threat model this tool was built against, the controls that implement it,
the assumptions those controls rest on, and what to change before running it
against production.

Written to be read by a security reviewer who has never seen the code. Where a
control is weaker than it might appear, this document says so.

---

## 1. What the tool is, from a security point of view

A **client-side** utility that runs as the operator's own user on the operator's
own workstation. It:

- holds plaintext credentials in process memory for the life of a session,
- opens outbound SSH and WinRM connections through a declared chain of hosts,
- executes commands supplied by version-controlled YAML on remote servers,
- writes an append-only audit trail to the local filesystem.

It grants no access the operator does not already have. It has no server, no
inbound listener beyond loopback, no user database, and no privileged component.

---

## 2. Threat model

### 2.1 Assets

| # | Asset | Where it lives |
|---|---|---|
| A1 | Hop and target passwords | Process memory of the `ac connect` process only |
| A2 | SSH private keys and passphrases | `~/.ssh` (never read into config); passphrase in memory |
| A3 | The session token | `%LOCALAPPDATA%\access_control\sessions\<host>.json`, mode `0600` |
| A4 | The authenticated path itself | The live SSH transports and PSRP runspace |
| A5 | Captured server output (logs, event records) | `<log dir>` on the workstation |
| A6 | The audit trail | `<log dir>/*.jsonl` |
| A7 | Topology (`inventory.yaml`) | The repository — deliberately shareable |

### 2.2 Actors

| Actor | Trust | Capability |
|---|---|---|
| **Operator** | Trusted | Types every credential; approves every gated action |
| **Agent (Claude or any script)** | Semi-trusted | Drives the CLI; never sees a credential; cannot answer a prompt |
| **Another process running as the operator** | Untrusted-but-unbounded | Can read the descriptor and drive the session. **Not defended against** |
| **Another user on the workstation** | Untrusted | Blocked by loopback binding and `0600` |
| **The bastion** | Semi-trusted | Sees SSH traffic and forward requests; not the WinRM payload |
| **The Windows jump server** | Semi-trusted | On a nested route it *executes* `Invoke-Command` and therefore holds the target credential briefly |
| **The target** | Untrusted | Runs our commands; **never supplies instructions back** |
| **The network between hops** | Untrusted | SSH plus WinRM message encryption |

### 2.3 Threats and the control that answers each

| # | Threat | Control | Residual risk |
|---|---|---|---|
| T1 | Credential theft at rest | Nothing is stored — no keyring, vault, file, or env var by default. Wiped on disconnect | A memory-scraping process running as the operator |
| T2 | Credential leaking into logs, output, or a traceback | Global redaction registry; `ExecResult` and `RedactingError` scrub themselves | A secret shorter than 4 characters is not registered |
| T3 | Credential typed into a chat and recorded in a transcript | Prompting bypasses the agent entirely (TTY or Windows dialog); the agent cannot drive a prompt | Social engineering of the operator |
| T4 | Credential on a command line, visible in the process table | No credential is ever passed as an argument. `ac rdp --stage-credentials` is the one exception and is **off by default** | Only when staging is explicitly enabled |
| T5 | Password sent to the wrong machine | Prompt labels name role, environment, identity, address and the hop it is reached through | Operator inattention |
| T6 | Commands run on the wrong host after a stale/reused port forward | `preflight.check_identity` asks the machine its own name; `--expect-hostname` pins it | Only if `expect_hostname` is omitted (a validation warning) |
| T7 | Agent escalating beyond intent | Five independent gates (§4); a compromised target cannot supply instructions | The `run-command` escape hatch, gated but powerful |
| T8 | Catastrophic command (`mkfs`, `rm -rf /`, `Format-Volume`) | `safety.py` deny-list checked immediately before every send, no override for `BLOCKED` | A pattern list will not catch everything |
| T9 | Man-in-the-middle on a hop | Host-key verification; a **changed** key is always fatal | An **unknown** key is accepted under the default `accept-new` |
| T10 | Bastion reading the Windows payload it forwards | pypsrp `encryption="auto"` seals WinRM messages inside the SSH tunnel | The bastion still sees traffic volume and destination |
| T11 | Target credential written to the jump server's event log | It is bound as a **PSRP parameter**, never interpolated into script text (PowerShell 4104 records the script body, not argument objects) | The jump server still holds it in memory during the call |
| T12 | A forward exposing a production server to the LAN | Every listener binds `127.0.0.1` only | — |
| T13 | Another user hijacking a live session | Loopback-only socket + 256-bit token in a `0600` file, compared with `compare_digest` | **Not** a defence against the same user |
| T14 | Captured server output leaving the organisation | Logs are written outside the repository, so a synced folder does not upload them | An operator overriding `logging.path` back inside the repo |
| T15 | Audit tampering | Records are flushed and `fsync`ed per action | **Written by the audited process — not tamper-evident** |
| T16 | Route drifting into a forbidden environment | `context.environment` is a hard boundary during resolution | Only where `environment` is actually set |
| T17 | Prompt injection via server output reaching the agent | Instructions come only from repo-controlled YAML; the target is acted upon, never consulted | An agent that treats captured log text as instruction — see [CLAUDE_PRODUCTION_GUARDRAILS.md](CLAUDE_PRODUCTION_GUARDRAILS.md) |

### 2.4 Explicitly out of scope

- Malware running as the operator's own user.
- A compromised workstation.
- Enforcement of the route graph against a determined human — the estate's
  `sshd_config`, firewalls and account rights remain the real control.
- Tamper-evident, chain-of-custody session recording (use Teleport or a PAM
  product).
- Multi-user approval workflows and RBAC (there is one operator per session).

---

## 3. Authentication

### 3.1 Where credentials come from

`credentials.select_prompter()` picks, in order:

| Prompter | Chosen when | Behaviour |
|---|---|---|
| `TerminalPrompter` | `stdin.isatty()` | `getpass` on the controlling terminal. Preferred |
| `WindowsCredUIPrompter` | Windows + `pywin32` + not disabled | Native `CredUIPromptForCredentials` dialog on the desktop; `DO_NOT_PERSIST` and `EXCLUDE_CERTIFICATES` flags set |
| `UnavailablePrompter` | neither | Fails with instructions to run `ac connect`. **Never silently degrades** |

Forced with `AC_PROMPTER=terminal|windows|none`; the dialog can be disabled with
`AC_NO_GUI_PROMPT`.

Both real prompters require a human. Neither can be driven by an agent — which is
the property that keeps a password out of a conversation transcript.

### 3.2 Per-hop authentication

Every hop is prompted **separately** and its credential is stored under that
node's id. The prompt label is deliberately verbose:

```
== CVT SSH bastion [CVT] [operator@bastion-staging.example.net:2222] ==
   user: operator
   password:
```

role/description · environment · identity · address · (via which hop). Typing a
bastion password into a target's prompt is the mistake the label exists to
prevent.

### 3.3 SSH authentication sequence

```
agent keys (auth.method: agent)
  → publickey            (auth.method: key | key+password)
      PartialAuthentication → the server names what it still wants
  → password             (auth.method: password | key+password | server-requested)
  → keyboard-interactive (MFA/OTP, server wording passed through verbatim)
```

- `key+password` is a genuine **multi-factor chain**, matching OpenSSH
  `AuthenticationMethods publickey,password`.
- If the key is rejected and a password stage follows, the failure message says
  the key was already rejected — because no password can then succeed, and the
  usual cause is a wrong username, not a wrong password.
- A **rejected credential is discarded**, never retried.
- A keyboard-interactive challenge with a single hidden "password" prompt is
  answered from the stored credential; anything else (an OTP, a security
  question) goes to the human with the server's own text.

### 3.4 Windows authentication

- Username is qualified to `DOMAIN\user` when `domain:` is set. A bare name fails
  against a domain-joined host and the failure *looks like* a wrong password.
- **NTLM** by default: the endpoint is a loopback tunnel address with no matching
  SPN, so Kerberos cannot work there.
- `encryption="auto"` keeps message-level encryption on even over plain HTTP, so
  the payload is sealed inside the SSH tunnel.
- The nested Windows→Windows leg builds a `PSCredential` **on the jump server**
  from a bound parameter, and removes the variables in a `finally` block.

### 3.5 NTLM provider selection

`auth.ntlm_provider` (default `auto`) chooses which implementation computes the
NTLM response:

| Value | Implementation | When `auto` picks it |
|---|---|---|
| `sspi` | Windows LSA / SSPI | The leg is tunnelled or pre-established (originates to `127.0.0.1`) |
| `python` | `spnego` pure-Python NTLM | The leg is **direct** — no bastion, no tunnel |

**Why this exists, stated plainly.** On a workstation whose Group Policy sets
*Restrict NTLM: Outgoing NTLM traffic = Deny* with an allow-list that does not
include the target, SSPI refuses locally with `SEC_E_LOGON_DENIED` (`0x8009030C`)
*before a packet is sent* — indistinguishable from a wrong password. The
pure-Python provider does not consult the LSA allow-list, so it succeeds.

**That is a deliberate step around a corporate control.** It is scoped to direct
routes, it is recorded in a `winrm.ntlm_provider` audit event, and the compliant
path is the bastion (where SSPI works because the exchange is to loopback). Treat
enabling it as a policy decision, not a configuration tweak, and raise it with
whoever owns the NTLM restriction.

### 3.6 Host-key verification

| Situation | Behaviour |
|---|---|
| Key matches `known_hosts` | Proceed, recorded as `known` |
| Key **changed** | **Fatal under every policy.** Nothing is sent. This is the interception signature |
| Key unknown, `AC_HOST_KEY_POLICY=accept-new` (default) | Accepted, appended to `known_hosts`, fingerprint recorded in a `host_key.new` audit event |
| Key unknown, `AC_HOST_KEY_POLICY=strict` | Refused, with the command to record it by hand |
| `known_hosts` malformed | Treated as empty (conservative: falls through to the unknown path) and recorded as `host_key.unreadable` |

**Production hardening:** seed `known_hosts` out of band, then set
`AC_HOST_KEY_POLICY=strict`.

---

## 4. Authorization model

There is no user database. Authorization is the intersection of five gates, each
of which can only subtract capability:

| # | Gate | Enforced by | Bypass |
|---|---|---|---|
| 1 | **Reachability** — the route must be declared, unambiguous, and must not cross an environment boundary | `routegraph.resolve` at load *and* connect time | None in-tool |
| 2 | **Catalogue binding** — the operation's `host_ids`/`tags` must include this host | `Operation.applies_to` | None |
| 3 | **Session allow-list** — `ac connect --ops a,b` | `Session.permits` | Reconnect with a wider list |
| 4 | **Permission gate** — gated/destructive operations need `--confirm`, and the refusal quotes the fully rendered commands | `Engine._check_permission` | The operator approving |
| 5 | **Command deny-list** — every rendered command is classified immediately before it is sent | `safety.check` | `CONFIRM` by confirming; `BLOCKED` **never** |

Two structural properties behave like authorization:

- **Instructions are central, never on the target.** `operations.yaml`, briefs
  and campaigns live in the repo, reviewed and version-controlled. A compromised
  host cannot hand work to a privileged, credentialed session — the "lethal
  trifecta" failure mode.
- **A degraded session authorizes nothing.** If the target leg failed and the
  session is held at a hop, the catalogue returns an empty list and `exec` is
  refused unless the caller explicitly declares it knows it is on the hop (only
  the operator's own prompt does).

### 4.1 The command deny-list

| Tier | Behaviour | Examples |
|---|---|---|
| **BLOCKED** | Refused outright. No flag overrides it | `Format-Volume`, `Clear-Disk`, `mkfs`, `dd of=/dev/sd*`, `shred`, `wipefs`, `rm -rf` of a root, drive-root `Remove-Item -Recurse`, fork bomb, `chmod -R 777 /`, `cipher /w`, `Disable-PSRemoting`, `netsh advfirewall set allprofiles state off` |
| **CONFIRM** | Needs explicit confirmation | reboot/shutdown/`init 0|6`, service stop/restart, `Remove-Item`, POSIX `rm`/`mv`/`truncate`/`chown`/`chmod`, `kill`/`pkill`, `crontab`, `msiexec /x`, `uninstall-*`, `Set-ExecutionPolicy`, HKLM registry writes, `reg add|delete`, `dism /add|remove-package`, `wusa`, `net user /add|/delete`, `useradd`/`userdel`/`usermod`, `yum`/`apt` install/remove/upgrade, `Install|Uninstall-WindowsFeature` |
| **ALLOWED** | Runs | everything else |

Details that matter:

- Whole-line `#` comments are stripped first, so prose describing an exit code
  (`# 3010 = installed, needs a reboot`) is not policed as an instruction.
- The rules are ordered and **first match wins**, so `BLOCKED` entries precede
  `CONFIRM`.
- The list applies **uniformly** to catalogue steps, `ac exec`, diagnostic
  collectors, brief-declared preflight checks, and the operator's own prompt
  (where `CONFIRM` is implicitly satisfied by a human typing it, but `BLOCKED`
  still holds).
- Preflight custom checks must be `ALLOWED` outright — a check that changes state
  is refused, because preflight verifies state rather than creating it.

**Honest framing:** this is not a sandbox. An operator with a shell can always do
more damage than a pattern list anticipates, and a sufficiently creative command
will evade any regex. It exists to stop an agent turning a plausible-looking
mistake into an outage — a real and common failure mode. Use `sudoers` and Windows
account rights *as well*, not instead.

---

## 5. Secrets management

| Question | Answer |
|---|---|
| Where are credentials stored? | **Nowhere.** Process memory only, in `CredentialStore`, keyed by node id |
| How long do they live? | Until `disconnect`, an idle timeout, or process exit. `discard_after_auth` can drop the plaintext immediately after authentication, but is off by default because sudo and post-reboot reconnects need it again |
| Are they ever written to disk? | No. Not to config, not to logs, not to the session descriptor |
| Do they cross the session socket? | No. `credentials_for` returns a **username only** |
| Can an agent read one? | No. No CLI command and no daemon method returns a password |
| What about the environment? | Only if `AC_ALLOW_ENV_CREDENTIALS` is explicitly enabled — a testing-only escape hatch |
| Private keys? | Read from `auth.key_file` at connect time; passphrase prompted, held in memory, wiped with everything else |

### 5.1 Redaction

Every secret is registered in a process-global registry the moment it is
collected, and every string that leaves the process passes through the scrubber:

- `ExecResult` scrubs `command`, `stdout`, `stderr` and all PowerShell streams
  **on construction**, so a password echoed by a remote command cannot reach a
  log even if nobody filtered it at the call site.
- `RedactingError` scrubs its own message, so a traceback cannot leak a
  credential embedded in a connection string.
- `AuditLog.emit` runs `redact_obj` over every field recursively.
- The library log handler applies a redacting filter before writing.
- Backslash-escaped variants are registered too, since a Windows password can
  arrive at a remote shell re-escaped.
- Secrets shorter than 4 characters are **not** registered — masking a
  3-character string would corrupt unrelated output far more than it protects.

Verified by test: the end-to-end audit trail on disk contains neither the bastion
nor the target password.

### 5.2 What is safe to share

| Artefact | Safe to commit / paste |
|---|---|
| `config/inventory.yaml`, `operations.yaml`, briefs, campaigns | **Yes** — topology and intent, no secrets |
| Audit trail (`*.jsonl`) and session summary (`*.md`) | Secrets are scrubbed, but they contain **captured server output** — treat as internal |
| Operation reports (`summary`) | Same: scrubbed of secrets, may contain log excerpts |
| `transport.log` | Redacted, but may name hosts and ports |

`.gitignore` blocks `*.key`, `*.pem`, `*.ppk`, `*.pfx`, `*.p12`, `.env*`,
`secrets*`, `*credential*`, `*password*`, `logs/` and `*.jsonl`.

---

## 6. Session management

| Property | Value |
|---|---|
| Transport | TCP on `127.0.0.1`, ephemeral port |
| Authentication | 256-bit `secrets.token_urlsafe(32)`, compared with `compare_digest` |
| Token storage | `sessions/<host>.json`, created with `O_CREAT|O_TRUNC` at mode `0600` **before** anything is written |
| Concurrency | One session per host id; `ac connect` refuses a second |
| Idle timeout | 1800 s default, `--idle-timeout 0` disables. Watchdog polls every 15 s, emits `session.idle_timeout`, wipes credentials |
| Request limit | 8 MiB per request and per response |
| Failure isolation | One bad request cannot kill the session; errors are returned, not raised |
| Teardown | Tunnels → channels → hops, in reverse, then `creds.clear()` and `redact.clear()` |
| Stale descriptors | Removed automatically when `attach()` finds nothing answering |

**Stated plainly: the socket is a convenience boundary, not a privilege
boundary.** Any process running as the same user can read the descriptor and
drive the session — the same trust level as an `ssh-agent` socket or a browser's
cookie store, and appropriate here because everything the session can do, the
user could already do. It protects against *other* users on the machine and
against the network. It does not protect against malware running as you.

---

## 7. Encryption

| Leg | Protection |
|---|---|
| Workstation → bastion | SSH (Paramiko defaults; host key verified) |
| Bastion → next hop | SSH `direct-tcpip` channel inside the first SSH session |
| Loopback forward → WinRM | The transport is plain HTTP on 5985, **but** pypsrp `encryption="auto"` seals every message, and the whole thing rides inside the SSH tunnel |
| Direct WinRM (`via: from: local`) | Message-level encryption only — **there is no SSH tunnel around it.** Use `winrm-ssl` (5986) where the estate offers it |
| Jump → target (nested) | The jump server's own WinRM session, `-Authentication Negotiate` |
| RDP | Whatever `mstsc` negotiates, inside the forward |
| At rest | None. Logs are plaintext JSON on the local filesystem — rely on disk encryption and filesystem permissions |

---

## 8. Audit logging

One JSON object per action, flushed and `fsync`ed immediately, so an abrupt
termination still leaves a complete trail up to the last action.

```json
{"timestamp": "2026-08-12T09:15:22.431+00:00", "seq": 14,
 "agentId": "AGT-20260812-001", "sessionId": "SES-845921",
 "host_id": "linux-app01", "event": "ssh.connect", "action": "SSH_CONNECT",
 "source": "JumpServer01", "target": "linux-app01", "result": "SUCCESS",
 "endpoint": "10.20.4.20:22", "channel": "ssh", "username": "appuser",
 "auth_methods": ["publickey", "password"], "host_key": "known",
 "context": {"environment": "QA", "owner": "AppOps"}, "duration_s": 0.81}
```

Identity fields use canonical spellings (`timestamp`, `agentId`, `sessionId`,
`action`, `source`, `target`, `result`) so the trail drops into a SIEM without a
transform step. Payload fields keep snake_case.

**Sixteen canonical actions:** `ROUTE_RESOLVE`, `SSH_CONNECT`, `WINRM_CONNECT`,
`RDP_LAUNCH`, `TUNNEL_OPEN`, `AUTHENTICATE`, `COMMAND_EXECUTE`,
`SCRIPT_EXECUTE`, `FILE_UPLOAD`, `FILE_DOWNLOAD`, `LOG_COLLECT`,
`PERMISSION_REQUEST`, `COMMAND_BLOCKED`, `SESSION_START`, `SESSION_END`,
`ERROR`. Full field reference:
[implementation/audit-events.md](implementation/audit-events.md).

**Security-relevant events to alert on** are listed in
[OPERATIONS.md](OPERATIONS.md#42-signals-worth-alerting-on).

**Limitation:** the trail is written by the process being audited. It is
excellent for "what did the agent do, and why did it fail". It is **not**
tamper-evident and is not a chain-of-custody artefact. If you need that, the
recording has to happen somewhere the operator does not control — a proxy or a
PAM product.

---

## 9. Known security assumptions

Each of these is load-bearing. If one is false in your environment, the control
above it is weaker than it looks.

1. **The operator's workstation is trusted.** Credentials are in its memory and
   the session descriptor is readable by anything running as that user.
2. **The operator reads the prompt label** before typing a password.
3. **`context.environment` is populated** on every node — the QA→PROD boundary
   check is a no-op where it is blank.
4. **`known_hosts` is meaningful.** Under the default `accept-new`, the *first*
   contact with each host is trust-on-first-use.
5. **The bastion and jump server are not hostile.** The jump server holds the
   target credential in memory during a nested call.
6. **The deny-list is a safety net, not a boundary.** OS-level controls
   (`sudoers`, account rights, WinRM ACLs) remain the real enforcement.
7. **Captured server output is not sensitive enough to require encryption at
   rest** on the workstation. If it is, encrypt the disk and lock down
   `<log dir>`.
8. **YAML config is trusted input.** Anyone who can edit `operations.yaml` can
   run arbitrary commands on the hosts it binds to — treat it as code and require
   review.
9. **`yaml.safe_load` is used everywhere**, so config cannot instantiate
   arbitrary Python objects.
10. **The agent is not adversarial**, only fallible. Controls stop mistakes, not
    a deliberately malicious client running as the operator.

---

## 10. Production hardening checklist

Before pointing this at production:

- [ ] `AC_HOST_KEY_POLICY=strict`, with `known_hosts` seeded out of band.
- [ ] `AC_ALLOW_ENV_CREDENTIALS` **unset** everywhere (verify: it is not in any
      profile, task, or CI definition).
- [ ] `context.environment` set on **every** node, so the boundary check is real.
- [ ] Production and non-production hosts in separate inventories, or at minimum
      with distinct `environment` values and no shared bastion edge.
- [ ] `logging.path` on a local, backed-up, access-controlled directory, forwarded
      to the SIEM; `retention_days` matching policy.
- [ ] `<log dir>` and `<sessions dir>` ACLs restricted to the operator.
- [ ] Full-disk encryption on the workstation.
- [ ] Operations reviewed as code: every `host_ids: ['*']` justified, every
      `requires_permission: false` genuinely read-only.
- [ ] Every brief sets `expect_hostname` and `success_criteria`.
- [ ] `--ops` used to scope any session handed to an agent.
- [ ] A bounded `--idle-timeout` (do not use `0`).
- [ ] `auth.transport: credssp` used nowhere, or explicitly approved.
- [ ] `ntlm_provider: python` / `AC_WINRM_PYTHON_NTLM` used nowhere, or explicitly
      approved with the NTLM policy owner.
- [ ] Least-privilege service accounts on the targets — this tool inherits
      whatever the account can do.
- [ ] `.ppk` keys converted; key files outside the repository; passphrases on
      keys.
- [ ] The repository's `.gitignore` unmodified, and `git status` clean of logs.
- [ ] Agent guardrails from
      [CLAUDE_PRODUCTION_GUARDRAILS.md](CLAUDE_PRODUCTION_GUARDRAILS.md) applied.

---

## 11. Security best practices for daily use

1. **Never type a password into a chat.** If an agent reports "no live session",
   it is asking *you* to run `ac connect` — not asking for your password.
2. **Run `ac verify <host> --expect-hostname <NAME>` before real work**, and again
   after anything that might have disturbed the path.
3. **Preview before approving.** Approving `Install {{package}}` is not informed
   consent; `ac preview` shows the rendered command.
4. **Scope the session** with `--ops` when handing it to an agent.
5. **Prefer named operations over `run-command`.** Anything done twice belongs in
   the catalogue, where it gets expectations, diagnostics and review.
6. **Close sessions when done** — `ac disconnect` wipes credentials immediately
   rather than waiting for the idle timeout.
7. **Treat `operations.yaml` as code.** Review changes; it is the only thing
   standing between an agent and arbitrary commands.
8. **Read the whole `inventory is invalid:` list** rather than fixing the first
   line — validation reports every problem in one pass on purpose.
9. **Keep the bastion path.** The direct/VPN route exists for a specific reason
   and skips every hop control.
10. **Do not relax `.gitignore`.**

---

## 12. Incident response

### 12.1 Evidence available

| Question | Where to look |
|---|---|
| What ran, where, when, by whom? | `<log dir>/<trace_id>.jsonl`; `ac audit <session-id>` |
| In what order, and how long did each take? | `ac timeline <session-id>` |
| Which hops were authenticated, with what identity and method? | `SSH_CONNECT` / `WINRM_CONNECT` records: `username`, `domain`, `auth_methods`, `host_key`, `endpoint`, `context` |
| What was refused? | `COMMAND_BLOCKED`, `PERMISSION_REQUEST` with `result: BLOCKED` |
| What did an operation actually do? | `<session>-NN-<operation>.md`, and the `summary` field in the result |
| Was there a wrong-host event? | `PREFLIGHT` records with `target.identity` failing |
| Did a route bypass the bastions? | `winrm.direct` events |
| Did NTLM policy get stepped around? | `winrm.ntlm_provider` events with `provider: python` |
| Was a host key new or unreadable? | `host_key.new`, `host_key.unreadable` |
| Did the session degrade or recover? | `session.degraded`, `session.recovered` |
| Unexpected crash? | `<log dir>/errors.log`; library detail in `transport.log` |

Correlate by `sessionId` (one authenticated path), `agentId` (one run), and
`trace_id` (the file name).

### 12.2 Immediate containment

```powershell
uv run ac status                     # every live session on this machine
uv run ac disconnect <host>          # closes and wipes credentials NOW
```

Closing the `ac connect` window achieves the same: credentials exist only in that
process. Then:

1. Rotate the credentials for **every hop touched** in the affected sessions.
   They were in memory; assume exposure if the workstation is suspect.
2. Preserve `<log dir>` before anything prunes it (retention deletes on next
   session start). Copy the whole directory out.
3. Check `sessions/` for descriptors that outlived their process.

### 12.3 Specific scenarios

| Scenario | Response |
|---|---|
| **`HOST KEY MISMATCH`** | Nothing was sent. Do **not** delete the `known_hosts` line. Confirm with the server owner whether the host was rebuilt. If not, treat as an interception attempt and escalate |
| **Wrong-host run detected** | Stop. Read `ac timeline` for what actually executed on the wrong machine. Check `ac routes <host>` for the address that resolved. Remediate on the wrong host before retrying |
| **A `BLOCKED` command appears in the trail** | It did **not** run. Investigate who or what issued it — an agent proposing `Format-Volume` is a signal about the instruction it was given |
| **Workstation compromise suspected** | Assume every credential typed on it is exposed. Rotate all of them. Assume the session token and any live session were usable by the attacker |
| **Repository compromise** | `operations.yaml` is executable content. Review its history for injected steps before running anything |
| **Credential appears unredacted in a log** | Report as a defect with the file and line. Check whether the secret was under 4 characters (not registered) or reached a path outside the scrubber |

### 12.4 Reporting a vulnerability

Report to the repository owner (see `pyproject.toml`) through your organisation's
internal security channel. Include the version (`ac version`), the redacted
records, and the reproduction path. Do not include real credentials.
