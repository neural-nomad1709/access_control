# Configuration reference

Every setting the tool reads, where it comes from, what it defaults to, and which
ones have security consequences.

**No configuration file holds a secret.** Inventory, operations, briefs and
campaigns contain topology, capability and intent only. Every password is typed
by a human at connect time and is never written anywhere.

| Source | What it configures | Precedence |
|---|---|---|
| `config/inventory.yaml` | Nodes, connectivity, logging, agent id prefixes | Base |
| `config/operations.yaml` | The operation catalogue | Base |
| Task brief YAML | One job on one host | Per run |
| Campaign YAML | A fan-out of one brief across hosts | Per run |
| CLI flags | Per-invocation overrides (`--ops`, `--idle-timeout`, …) | Over config |
| Environment variables | Paths, prompting, host-key policy, test escape hatches | Over config |

---

## 1. Filesystem locations

Resolved by `paths.py`. **Audit logs and session state deliberately live outside
the repository** — this project is expected to sit in a synced folder, and
captured server output must not be uploaded.

| Purpose | Windows default | Linux/macOS default | Override |
|---|---|---|---|
| App data root | `%LOCALAPPDATA%\access_control` | `$XDG_DATA_HOME/access_control` or `~/.local/share/access_control` (macOS: `~/Library/Application Support/access_control`) | `AC_DATA_DIR` |
| Audit logs & summaries | `<root>\logs` | `<root>/logs` | `logging.path`, then `AC_LOG_DIR` |
| Live session descriptors | `<root>\sessions` | `<root>/sessions` | via `AC_DATA_DIR` |
| Config directory | `<repo>\config` | `<repo>/config` | `AC_CONFIG_DIR`, or `AC_HOME` (repo root) |
| Known hosts | `~/.ssh/known_hosts` | same | `AC_KNOWN_HOSTS` |

Files written under `logs/`:

| File | Content |
|---|---|
| `<trace_id>.jsonl` | The append-only audit trail for one session |
| `<trace_id>.md` | Human-readable session summary written on close |
| `<session_id>-NN-<operation_id>.md` | Shareable per-operation report |
| `transport.log` | Paramiko / pypsrp / spnego library logging, redacted |
| `errors.log` | Tracebacks of unexpected (non-`AccessControlError`) failures |

---

## 2. Environment variables

| Variable | Default | Effect | Security note |
|---|---|---|---|
| `AC_DATA_DIR` | platform default | Root for logs, sessions, state | Point at a local disk, never a synced folder |
| `AC_LOG_DIR` | `logging.path`, else `<root>/logs` | Highest-precedence audit log directory | Use to feed a SIEM collection path |
| `AC_CONFIG_DIR` | `<repo>/config` | Where `inventory.yaml` / `operations.yaml` are read from | — |
| `AC_HOME` | repo root inferred from the package location | Project root (the directory holding `config/`) | — |
| `AC_AGENT_ID` | `AGT-<date>-<seq>` | Pins the agent id on every record | Set it per pipeline/run so trails correlate |
| `AC_PROMPTER` | auto | Force a prompter: `terminal`, `windows`\|`gui`\|`dialog`, `none` | `none` disables prompting entirely |
| `AC_NO_GUI_PROMPT` | unset | Any value disables the Windows credential dialog | Forces terminal-only prompting |
| `AC_HOST_KEY_POLICY` | `accept-new` | `strict` refuses an unknown host key; a *changed* key is fatal under both | **Set `strict` for production hardening** |
| `AC_KNOWN_HOSTS` | `~/.ssh/known_hosts` | Alternate known-hosts file | — |
| `AC_WINRM_PYTHON_NTLM` | unset | `1`/`true`/`yes` forces the pure-Python NTLM provider process-wide | Steps around a "Restrict NTLM outgoing" policy — see [SECURITY.md](SECURITY.md#35-ntlm-provider-selection) |
| `AC_ALLOW_ENV_CREDENTIALS` | unset | `1`/`true`/`yes` allows credentials from the environment | **Testing only. Never set this on a machine with production access** — it defeats the manual-entry requirement |
| `CLAUDECODE` / `CLAUDE_CODE` | set by the harness | Makes the default agent id `claude-code@<hostname>` | Read-only signal |

### Per-node credential variables (only with `AC_ALLOW_ENV_CREDENTIALS`)

The node id is upper-cased with every non-alphanumeric character replaced by `_`:

```
AC_PASSWORD_<NODE>          e.g. node id "bastion-staging"  →  AC_PASSWORD_BASTION3_CVT
AC_KEY_PASSPHRASE_<NODE>
AC_USERNAME_<NODE>          used only where prompt_username applies
```

Values supplied this way are still registered for redaction, but they exist on
disk or in a process environment — which is precisely what the design otherwise
avoids. Use them in CI against fake servers, nowhere else.

---

## 3. `config/inventory.yaml`

Four top-level keys, all optional except `hosts`.

```yaml
logging: {...}
agent:   {...}
hops:    {...}      # machines on the way: bastions, jump servers
hosts:   {...}      # final targets (at least one required)
routes:  [...]      # older alternative to per-node `via:` — cannot be combined with it
```

### 3.1 `logging:`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | `false` keeps the in-memory trail (so `ac status` works) but writes nothing to disk |
| `path` | string | platform default | Expands `~` and `%VARS%`. Point at a collected directory for SIEM ingestion. **Never inside the repo.** |
| `retention_days` | int ≥ 0 | `30` | `0` keeps everything. Pruning of `*.jsonl` / `*.md` older than this runs when a session starts, and never raises |
| `level` | enum | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR`. Validated; an unknown value is a load error. Currently recorded and reported but not yet used to filter records |

`AC_LOG_DIR` overrides `path`.

### 3.2 `agent:`

| Key | Default | Produces |
|---|---|---|
| `id_prefix` (alias `prefix`) | `AGT` | `AGT-20260812-3f9a1c`, one per run |
| `session_prefix` | `SES` | `SES-3f9a1c`, one per authenticated path |

The suffix is random (6 hex chars), so concurrent sessions on one machine never
share an id — there is no persisted counter and nothing to race on. An explicit
id wins outright: `ac connect --agent-id`, then the `AC_AGENT_ID` environment
variable, then the generated form.

### 3.3 Node fields (`hops:` and `hosts:` take the same shape)

| Field | Type | Default | Notes |
|---|---|---|---|
| `role` | enum | `node` | `bastion` \| `jump` \| `target` \| `node`. Labels only — routing does not depend on it |
| `kind` | enum | `ssh` | SSH kinds: `ssh`, `linux`, `unix`, `aix`, `solaris`. Windows kinds: `windows`, `win` |
| `hostname` (alias `host`) | string | taken from the first `via:` block | Required if there is no `via:` |
| `username` (alias `user`) | string | — | The identity to authenticate as |
| `domain` | string | `""` | Qualifies a bare username to `DOMAIN\user` on **every** node kind |
| `description` | string | `""` | Shown on the password prompt — make it unambiguous |
| `tags` | list[str] | `[]` | How operations bind to hosts |
| `vars` | mapping | `{}` | Extra `{{placeholders}}` for operation templates. `allow_direct: true` permits an empty `path:` |
| `context` | mapping | empty | See below |
| `auth` | mapping | see below | Never contains a secret |
| `port` | int | `22`, or the SSH port from `via:` | SSH port |
| `winrm_port` | int | `5985`, or the WinRM port from `via:` | |
| `rdp_port` | int | `3389`, or the RDP port from `via:` | |
| `automation` | enum | `winrm` for Windows kinds, `ssh` otherwise | `ssh` \| `winrm` \| `wmi` \| `none`. Non-Windows kinds may only use `ssh` or `none` |
| `interactive` | enum | `rdp` for Windows kinds, `ssh` otherwise | `rdp` \| `ssh` \| `none`. `rdp` requires a Windows kind |
| `via` | mapping or list | — | How this machine is reached. See §3.5 |
| `path` | list[str] | `()` | **hosts only.** Older linear shorthand: the ordered hop ids |
| `host_id` | string | the key | **hosts only.** If present it must equal the key |

Rejected outright:

| Field | Why |
|---|---|
| `package_share` | Paths belong to the job, not the machine. Declare it as an operation parameter and supply it in the brief, so a missing value is refused by name rather than rendering as an empty string |
| A `username` carrying a domain **and** a contradicting `domain:` | The login would silently use one and ignore the other |

### 3.4 `context:`

| Key | Default | Enforcement |
|---|---|---|
| `environment` | `""` | **Hard boundary** — a route may not cross differing values (case-insensitive). This is what stops a QA bastion becoming a path into production |
| `datacenter` | `""` | Recorded for audit only; crossing is routine |
| `network_zone` (alias `networkZone`) | `""` | Recorded for audit only |
| `owner` | `""` | Recorded for audit only |
| anything else | — | Kept in `extra` and emitted in audit records |

An empty `environment` on either side of a hop disables the check for that hop —
so leaving it blank is a decision, not a default safety net.

### 3.5 `via:` — how a machine is reached

```yaml
via:
  from: bastion1                    # node id, or `local` for this workstation
  # EITHER the inline shorthand (one channel):
  hostname: 10.20.4.11
  port: 5985                        # MANDATORY
  protocol: winrm
  # OR two explicit endpoints:
  automation:  {hostname: 10.20.4.11, port: 5985, protocol: winrm}
  interactive: {hostname: 10.20.4.11, port: 3389, protocol: rdp}
```

| Key | Required | Notes |
|---|---|---|
| `from` (alias `source`) | **yes** | The node this one is reached *from*. `local` is the operator's machine |
| `hostname` (alias `host`) | yes, per endpoint | **As seen from `from:`** — the same machine has different addresses from different vantage points |
| `port` | **yes** | Never defaulted. The error names what the default would have been |
| `protocol` | yes | `ssh` \| `winrm` \| `winrm-ssl` \| `rdp` \| `wmi` |
| `preestablished` | no (default `false`) | The address is the local end of a forward that already exists, so no second tunnel is built. **Implied automatically by `localhost` / `127.0.0.1` / `::1`** |
| `description` | no | Inherited from the node when omitted |

Rules:

- With the inline shorthand, the protocol decides the slot: RDP becomes the
  `interactive` endpoint, everything else becomes `automation`.
- **RDP under `automation` is rejected at load time.** It carries pixels, not
  exit codes.
- `via:` may be a **list** of blocks for a machine reachable from more than one
  place. Resolution still takes the shortest path and still refuses two of equal
  length as ambiguous — declaring alternatives does not license guessing.
- Identity (`username`, `domain`) is **never** restated on a leg; it is copied
  from the node's own block so the two cannot drift.

### 3.6 `auth:`

| Key | Type | Default | Applies to | Notes |
|---|---|---|---|---|
| `method` | enum | `password` | SSH | `password` \| `key` \| `key+password` \| `agent`. `key`/`key+password` require `key_file` |
| `key_file` | path | — | SSH | `~` and `%VARS%` expand. OpenSSH format; `.ppk` is detected and refused with conversion instructions |
| `transport` | string | `ntlm` | WinRM | `ntlm` (works through a tunnel, needs no SPN), `kerberos`, `credssp`, `basic`. **CredSSP delegates your credential to the target** — only with the security team's agreement |
| `ntlm_provider` | enum | `auto` | WinRM + `transport: ntlm` | `auto` \| `sspi` \| `python`. See below |
| `prompt_username` | bool | `false` | both | Ask for the username instead of taking it from the inventory. Also implied when no `username` is set |

**`ntlm_provider` resolution** — `auto` decides from the route the leg actually
took:

| Leg | `auto` resolves to | Why |
|---|---|---|
| Reached through a bastion tunnel, or a pre-established forward | `sspi` | The NTLM exchange originates to `127.0.0.1`, which "Restrict NTLM outgoing" does not block |
| Direct (`via: {from: local}`, no tunnel) | `python` | Windows SSPI would refuse locally with `SEC_E_LOGON_DENIED` before the server sees anything, if the client's Group Policy denies outgoing NTLM and the target is not allow-listed |

The resolved value is recorded in a `winrm.ntlm_provider` audit event alongside
what was configured. `AC_WINRM_PYTHON_NTLM=1` forces `python` process-wide,
regardless of config.

`key+password` maps to OpenSSH `AuthenticationMethods publickey,password`: the
key is offered, the server replies with a partial success, and the password
completes the login. Setting `password` alone against such a server fails after
the key stage.

### 3.7 `routes:` — the older declaration style

```yaml
routes:
  - source: local
    target: bastion1
    hostname: bastion1.example.net
    port: 2222
    protocol: ssh
  - source: bastion1
    target: jump1
    automation:  {hostname: 10.20.4.11, port: 5985, protocol: winrm}
    interactive: {hostname: 10.20.4.11, port: 3389, protocol: rdp}
```

Accepted, and compiles to exactly the same graph. It **cannot be combined with
any `via:` block in the same file** — connectivity declared twice is refused at
load time. Per-host `path: [bastion1, jump1]` is the third accepted style and
uses each node's own `hostname`/`port`.

### 3.8 Load-time validation

Everything below is raised when the file is *read*, before any socket opens:

- an id defined as both a hop and a host,
- a `path:` naming an unknown hop or visiting one twice,
- an empty `path:` without `vars.allow_direct: true`,
- an edge naming a node that is not declared,
- a duplicate `source → target` pair,
- a port outside 1–65535, or missing,
- an unknown `kind` / `role` / `automation` / `interactive` / `protocol`,
- RDP declared as automation, or an interactive-only intermediate hop,
- more than one Windows jump server, or SSH after WinRM,
- a route crossing an `environment` boundary,
- an unresolvable or ambiguous route for **any** host with `automation != none`,
- a username/domain contradiction.

---

## 4. `config/operations.yaml`

```yaml
operations:
  - id: install-package
    description: …
    tags: [windows]                 # or host_ids: [win-app01] / ['*']
    requires_permission: true
    destructive: false
    shell: powershell               # default shell for this operation's steps
    params: [...]
    steps: [...]
```

### 4.1 Operation fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | string | **required** | Unique across the file |
| `description` | string | `""` | Shown by `ac ops` |
| `host_ids` | list[str] | `()` | Exact host ids, or `['*']` for every host. An unknown id is a **hard error** |
| `tags` | list[str] | `()` | Matches any host carrying the tag. An unmatched tag is a warning |
| `params` | list | `()` | See below |
| `steps` | list | **required, non-empty** | Step ids must be unique |
| `requires_permission` | bool | **`true`** | Gated by default — an operation must opt *out* of asking |
| `destructive` | bool | `false` | Implied `true` if any step is destructive. Called out in the refusal message |
| `shell` | enum | `powershell` | Default for steps that do not set their own |

At least one of `host_ids` or `tags` is required: it must be unambiguous which
machines an operation may touch.

### 4.2 `params:`

```yaml
params:
  - name: package_share
    required: true
    description: Folder on the TARGET holding the package
  - name: install_args
    required: false
    default: "/quiet /norestart"
  - short_form            # a bare string means {name: short_form, required: true}
```

| Key | Default | Notes |
|---|---|---|
| `name` | **required** | The `{{placeholder}}` it fills |
| `required` | `true` unless a `default` is present | A missing required param is refused **by name**, before anything runs |
| `default` | `None` | Used when the caller supplies nothing |
| `description` | `""` | Shown to whoever writes the brief |

### 4.3 Step fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | string | **required** | Unique within the operation; used by `--start-at` / `--only` |
| `run` | string | **required** | The script. `{{placeholders}}` render strictly |
| `desc` (alias `description`) | string | `""` | Shown to the operator when approving |
| `shell` | enum | the operation's | `powershell` \| `cmd` \| `bash` \| `sh` |
| `timeout_s` | int | `600` | Wall clock. Installers need 1800–5400 |
| `destructive` | bool | `false` | Makes the whole operation gated |
| `requires_permission` | bool | `false` | Same effect at step level |
| `continue_on_failure` | bool | `false` | Carry on to the next step instead of stopping |
| `expect` | mapping | `{exit_code: 0}` | See below |
| `on_failure` | mapping | none | See below |

### 4.4 `expect:`

| Key | Default | Meaning |
|---|---|---|
| `exit_code` | `0` | Exact match |
| `any_exit_code` | `false` | Accept whatever comes back (sets `exit_code` to `None`) |
| `stdout_contains` | — | Substring must be present |
| `stdout_not_contains` | — | Substring must be absent |
| `stdout_regex` | — | `re.search` with `MULTILINE` |

All three string forms are **templated**, so `stdout_contains: '{{package}}'`
works. An unknown key inside `expect:` is a load-time error rather than being
silently ignored. A timed-out step fails regardless of the expectation.

### 4.5 `on_failure:`

```yaml
on_failure:
  collect:
    - files: ['C:\Windows\Temp\MSI*.LOG']
      tail_lines: 120                          # default 200
    - eventlog: {log: Application, newest: 25, level: error}
    - command: Get-Service MyApp | Format-List
  hints:
    "1603": Search the collected log for "Return value 3"
    "*":    Read the collected log before retrying
```

| Key | Notes |
|---|---|
| `collect[].files` | Globs; resolve to the **most recently written** match (installer logs have generated names) |
| `collect[].eventlog` | `{log, newest, level}` → `Get-WinEvent` on Windows; `journalctl`/syslog elsewhere. `level`: `critical`\|`error`\|`warning`\|`information` |
| `collect[].command` | An arbitrary diagnostic command — still classified by the deny-list, and a refusal is recorded rather than raised |
| `collect[].tail_lines` | Default `200` |
| `hints` | Keyed by exit code as a **string** (quote numeric keys), with `"*"` as the catch-all |

Collected output is truncated to the last 6 000 characters per source, and the
whole `ExecResult` is clamped to 20 000 characters (head + tail) before it
reaches a caller.

---

## 5. Task brief

Full worked guidance: [guides/instructions-guide.md](guides/instructions-guide.md).
Start from [`config/briefs/TEMPLATE.yaml`](../config/briefs/TEMPLATE.yaml).

```yaml
brief:
  id: TB-2026-0812-001        # REQUIRED
  title: …                    # REQUIRED
  host: win-target02            # REQUIRED — a host_id from inventory.yaml
  requested_by: amit.kala
  change_ref: CHG0043211
  window: "2026-08-12 22:00-23:00 AEST"
  description: >-  …

preflight: {...}
operations: [...]             # REQUIRED, non-empty
rollback:   [...]
success_criteria: [...]
must_not:   [...]
rules:      {...}
postcheck:  {...}             # parsed, but NOT executed — see note below
```

### 5.1 `preflight:`

| Key | Type | Effect |
|---|---|---|
| `expect_hostname` | string | Pins the target's own reported name. **Set this always** — a missing value is a validation warning |
| `require_free_disk_gb` | number | Fails if less is free |
| `disk_drive` | string | Drive letter (Windows) or path (Unix). Default `C` / `/` |
| `require_services_running` | list[str] | Windows `Get-Service`, or systemd/SRC (`lssrc`) on Unix |
| `abort_if` | list | `pending_reboot`, `active_msi_install` (alias `active_install`) |
| `checks` | list | `{name, run, expect_contains}` — arbitrary but **must be read-only**; a state-changing check is refused |

Four connection checks always run first, in this order, and a fatal failure stops
the rest: `session.live` → `chain.intact` → `target.responds` →
`target.identity`. A round trip slower than 5 s is reported as a warning, not a
failure.

### 5.2 `operations:` / `rollback:`

| Key | Default | Notes |
|---|---|---|
| `operation` (alias `id`) | **required** | Must exist in the catalogue and be permitted on the host |
| `params` | `{}` | Undeclared parameter names are a validation error |
| `on_failure` | `stop` | `stop` \| `continue` \| `rollback` (requires a `rollback:` block) |
| `start_at` | — | Resume an operation from this step |
| `only_steps` | `[]` | Run only these steps |
| `note` | `""` | Context shown at the approval prompt |

A bare string is accepted as shorthand for `{operation: <string>}`.

### 5.3 `rules:`

| Rule | Default | **Enforced?** |
|---|---|---|
| `confirm_destructive` | `true` | Advisory. Setting it `false` produces a validation warning; gating itself comes from the catalogue and `--confirm` |
| `stop_on_first_failure` | `true` | Yes, by `ac brief run` (each step's own `on_failure` decides first) |
| `reboot_allowed` | `false` | **Yes** — a brief listing an operation whose steps could restart the host is rejected at validation time |
| `max_duration_minutes` | `120` | **Not enforced.** Recorded and rendered for the reader only |
| `allow_diagnostic_commands` | `true` | Advisory to the agent |
| `allow_unlisted_operations` | `false` | Advisory to the agent |

A **misspelled rule is rejected**, not ignored — a silently-dropped
`reboots_allowed: true` would be the worst possible outcome.

> **`postcheck:` is parsed and returned by `ac brief show --json`, but nothing
> executes it.** Put verification in a final operation or in `success_criteria`
> until that is implemented. Tracked in [gap-analysis.md](gap-analysis.md).

---

## 6. Campaign

```yaml
campaign:
  id: qa-health-sweep           # REQUIRED
  title: QA fleet health sweep  # REQUIRED
  requested_by: operator
  change_ref: DEMO-HEALTH
  description: >- …
  max_parallel: 8               # default 8, minimum 1
  confirm: false                # pre-approve gated operations fleet-wide

targets:                        # REQUIRED, non-empty
  - host: win-target01-dev          # optional: overrides the brief's own `host:`
    brief: config/briefs/qa-health.yaml
    note: second QA app server
```

- A host may appear **once** per campaign — one host has one session.
- Brief paths resolve relative to the current directory, then the campaign file's
  directory, then its parent.
- Campaigns handle **no credentials**. Each host must already have a live session
  (`ac connect <host>`); hosts without one are reported and skipped, never
  connected to.
- `--parallel` on the CLI overrides `max_parallel`; `--confirm` ORs with
  `campaign.confirm`.

---

## 7. Timeouts, limits and other constants

Compiled-in defaults, listed so nothing is a surprise. Only those with a config
key are adjustable without a code change.

| Constant | Value | Config key |
|---|---|---|
| Session idle timeout | 1800 s | `ac connect --idle-timeout` (`0` = never) |
| Idle watchdog poll | 15 s | — |
| Step timeout | 600 s | `steps[].timeout_s` |
| `ac exec` timeout | 300 s | `--timeout` |
| Diagnostic collector timeout | 120 s | — |
| `fetch_log` timeout | 180 s | — |
| Preflight check timeouts | 45–120 s | — |
| Slow round-trip warning | 5 s | — |
| SSH connect / banner timeout | 30 s | — |
| SSH keepalive | 30 s | — |
| WinRM operation / read / connect timeout | 60 / 90 / 30 s | — |
| WinRM transparent retry after a transport wedge | 1 attempt | — |
| Session socket request timeout | 3600 s | — |
| Max request/response over the session socket | 8 MiB | — |
| Max `ExecResult` output | 20 000 chars (head + tail) | — |
| Max collected diagnostic per source | 6 000 chars | — |
| Default `tail_lines` | 200 | `collect[].tail_lines` |
| Campaign parallelism | 8 | `campaign.max_parallel` |
| Minimum length of a redacted secret | 4 chars | — |

---

## 8. Security-sensitive settings

Review these before running against production.

| Setting | Risk if wrong | Recommended |
|---|---|---|
| `AC_ALLOW_ENV_CREDENTIALS` | Credentials leave the "typed by a human" model and live in an environment or a file | **Never set outside tests** |
| `AC_HOST_KEY_POLICY` | `accept-new` trusts an unknown key on first contact, so a first connection could be intercepted | `strict` for production, after seeding `known_hosts` |
| `auth.ntlm_provider: python` / `AC_WINRM_PYTHON_NTLM` | Deliberately bypasses the client's "Restrict NTLM outgoing" Group Policy | Prefer the bastion path; get explicit approval before using direct routes |
| `auth.transport: credssp` | Delegates your credential to the target, which can then reuse it | Only with the security team's agreement; prefer a server-local package share |
| `logging.enabled: false` | No audit trail on disk | Leave `true` |
| `logging.path` inside the repo | Captured server output syncs to the cloud | Keep it outside the repository |
| `logging.retention_days: 0` | Trails accumulate forever | Match your retention policy; 30 is the default |
| `vars.allow_direct: true` | Bypasses every bastion for that host | Only for a genuinely direct/VPN route, and say so in `description` |
| `context.environment` left blank | The QA→PROD boundary check silently does nothing | Set it on every node |
| `--idle-timeout 0` | An authenticated session with live credentials lives until the window is closed | Keep a bounded timeout |
| `host_ids: ['*']` | Every operation applies to every host | Use tags or explicit ids |
| `requires_permission: false` | The operation runs without approval | Read-only operations only |
| `ac rdp --stage-credentials` | The password is on `cmdkey`'s command line for a few milliseconds | Leave off; let `mstsc` prompt |

---

## 9. Validating configuration

```powershell
uv run ac doctor                      # config parses, keys exist, prompting works
uv run ac hosts                       # every host and whether its route resolves
uv run ac routes                      # every declared edge + entry points
uv run ac routes <host>               # one resolved route, verbose, with context
uv run ac ops                          # the catalogue, params, and what is gated
uv run ac brief validate <brief.yaml> # offline; connects to nothing
uv run ac campaign validate <c.yaml>  # offline; also reports live sessions
uv run ac preview <host> <op> -p k=v  # the exact rendered commands
```

Add `--json` to any of them for machine-readable output.

Editing `operations.yaml` while a session is open? `ac reload <host>` re-reads
the catalogue without costing a password. It is **refused if the host's route
changed**, because the live connection would no longer match the config.
