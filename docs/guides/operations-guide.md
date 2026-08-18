# Operations guide

How to add a host and how to write an operation. Both are YAML; neither needs
code.

---

## Adding a host

Hosts and hops live in `config/inventory.yaml`. Copy the example first:

```powershell
copy config\inventory.example.yaml config\inventory.yaml
```

**No secrets go in this file.** It is meant to be committed and shared across the
company. Passwords are prompted for at connect time.

### A node

`hops:` are machines on the way (bastions, jump servers); `hosts:` are final
targets. Both take the same fields.

```yaml
hops:
  bastion1:
    role: bastion                  # bastion | jump | target | node
    kind: ssh
    hostname: bastion1.example.net
    port: 2222
    username: operator
    domain: corp                   # qualifies a bare username to corp\operator
    description: QA SSH bastion    # shown on the password prompt
    context:
      environment: QA              # a hard boundary -- routes may not cross it
      datacenter: East
      network_zone: Internal
      owner: PlatformOps
    auth:
      method: key+password         # password | key | key+password | agent
      key_file: ~/.ssh/id_rsa_operator
```

`description` and `context.environment` matter more than they look: together
they are what the operator reads when deciding which password to type. The
prompt reads `QA SSH bastion [QA] [corp\operator@bastion1.example.net:2222]`.

| `auth.method` | Meaning |
|---|---|
| `password` | Password only |
| `key` | Key only (its passphrase is prompted if needed) |
| `key+password` | Key, *then* password — OpenSSH `AuthenticationMethods publickey,password` |
| `agent` | Whatever the SSH agent offers |

Windows nodes use `auth.transport` instead of `method`:

| Key | Default | Meaning |
|---|---|---|
| `transport` | `ntlm` | `ntlm` (works through a tunnel, needs no SPN), `kerberos`, `credssp`, `basic` |
| `ntlm_provider` | `auto` | Which implementation computes the NTLM response. `auto` picks SSPI for a tunnelled leg and the pure-Python provider for a direct one — see [CONFIGURATION.md](../CONFIGURATION.md#36-auth) |

And on any node kind:

| Key | Default | Meaning |
|---|---|---|
| `prompt_username` | `false` | Ask for the username rather than taking it from the inventory. Implied when no `username` is set |

A target adds the fields operations bind to:

```yaml
hosts:
  win-app01:
    role: target
    kind: windows                  # windows | linux | unix | aix | solaris
    username: svc_deploy
    domain: corp
    tags: [windows, windows-2019, qa]
    context: {environment: QA, datacenter: East, network_zone: Internal, owner: AppOps}
```

`host_id`, `host`, `user` and `kind` are available to operations as
`{{placeholders}}`, as is anything under an optional `vars:` block.

**Paths a job works on do not belong here.** A package share or patch folder is a
fact about tonight's job, not about the machine — declare it as a parameter of
the operation that uses it and give the value in the brief. Putting it on the
host means every job on that host shares one value, and a missing one renders as
an empty string and fails on the server instead of being refused by name up
front. `package_share:` on a host is rejected at load time for that reason.

### Declaring how to reach it

**Connectivity is declared, never discovered.** A machine with no `via:` cannot
be traversed — and the tool will not fall back to a direct connection.

The leg goes inside the machine's own block, so there is exactly one place to
edit and nothing to keep in sync:

```yaml
hops:
  bastion1:
    kind: ssh
    username: operator
    auth: {method: key+password, key_file: ~/.ssh/id_rsa_operator}
    via:
      from: local                  # 'local' = the operator's machine
      hostname: bastion1.example.net
      port: 2222                   # mandatory, never defaulted
      protocol: ssh

  JumpServer01:
    kind: windows
    username: jumpuser
    domain: corp                   # identity is stated here, never on the leg
    auth: {transport: ntlm}
    via:
      from: bastion1
      automation:                  # how commands actually run
        hostname: 10.20.4.11       # as seen FROM bastion1
        port: 5985
        protocol: winrm
      interactive:                 # how a human gets a desktop
        hostname: 10.20.4.11
        port: 3389
        protocol: rdp

hosts:
  win-app01:
    kind: windows
    username: svc_deploy
    domain: corp
    via:
      from: JumpServer01
      automation:  {hostname: win-app01.corp.net, port: 5985, protocol: winrm}
      interactive: {hostname: win-app01.corp.net, port: 3389, protocol: rdp}
```

Points worth understanding:

- **Each leg is addressed from its `from:`.** The jump server is
  `localhost:44001` on your laptop and `10.20.4.11:3389` from the bastion. Both
  are expressible; `via:` says which applies where.
- **Identity is never restated on the leg.** `username` and `domain` come from
  the machine's own block. When they could be written in both places they drifted,
  and the copy on the leg was the one nothing read.
- **`preestablished: true`** means a tunnel already exists and this tool should
  dial it rather than build a second one on top. A loopback address implies it,
  because treating `localhost` as a real host would connect to your own machine.
  Start such a tunnel yourself:
  `ssh -p 2222 -L 44001:jump:3389 -L 45985:jump:5985 operator@bastion1.example.net`
- **`automation` and `interactive` are separate** because RDP carries pixels and
  cannot return an exit code. Declaring RDP under `automation` is rejected at
  load time.
- **Ports are mandatory.** Defaulting them is how a connection silently goes
  somewhere it was never meant to.
- **A machine reachable two ways** may give `via:` a list of blocks. Two ways in
  of equal length are still refused as ambiguous.

### Older spellings

A standalone `routes:` list of `{source, target, hostname, port, protocol}`
edges, and a per-host `path: [bastion1]` shorthand that uses each node's own
hostname and port, both still load and compile to the same graph.

They cannot be combined with `via:` in one file: connectivity declared in two
places is refused at load time.

### Then confirm it

```powershell
uv run ac routes                 # everything declared
uv run ac routes win-app01       # resolve one route, with context per hop
uv run ac hosts
uv run ac probe win-app01        # do those ports actually answer?
uv run ac probe win-app01 --deep # can the jump server reach the target?
```

`probe` is not optional courtesy. It is the only honest answer to "will this
work", and `--deep` is the only way to check the jump → target leg, because that
target is usually invisible from the bastion.

### What gets refused, and why

| Refusal | Reason |
|---|---|
| `No route defined between requested target and available bastion` | No declared edge reaches it. Add one; a direct connection will not be attempted. |
| `ambiguous route: N declared paths of equal length` | Traversal must be unambiguous. Remove an edge, or split the target per environment. |
| `crosses an environment boundary: QA -> PROD` | Environments are separated on purpose. |
| `port: required` | Ports are mandatory on every edge. |
| `cannot run commands` (RDP under `automation`) | RDP has no exit code. |
| `rdp-only, but a route passes through it` | A hop must run commands for the next leg to launch from it. |
| `N Windows jump servers. Only one is supported` | Nesting `Invoke-Command` deeper means passing a credential through an intermediate script. |

All of these are raised when the config is **read**, not when you connect — so
you find out before typing any passwords.

---

## Writing an operation

Operations live in `config/operations.yaml`. This is the configurable task list —
the agent can run nothing that is not in it, except the deliberately gated
`run-command` escape hatch.

### Minimal example

```yaml
operations:
  - id: restart-iis
    description: Restart the IIS application pool
    host_ids: [target1]           # or: tags: [windows-2019]
    requires_permission: true
    params:
      - name: pool
        required: true
    steps:
      - id: restart
        desc: Recycle the pool
        run: |
          Restart-WebAppPool -Name '{{pool}}'
        expect:
          exit_code: 0
```

### Binding to hosts

Every operation must declare `host_ids` or `tags`, so it is unambiguous which
machines it may touch.

```yaml
host_ids: [target1, target2]   # exact hosts
tags: [windows-2019]           # any host carrying that tag
host_ids: ['*']                # every host -- use sparingly
```

A `host_ids` entry naming a host that does not exist is a hard error at load
time, not a warning. Getting it wrong is how a patch job runs on the wrong
machine.

### Step anatomy

```yaml
- id: install                   # unique within the operation
  desc: Silent install          # shown to the operator when approving
  shell: powershell             # powershell | cmd | bash | sh
  timeout_s: 1800               # default 600
  destructive: true             # implies the operation needs approval
  requires_permission: false    # same effect at step level
  continue_on_failure: false    # default: stop the operation here
  run: |
    <your script>
  expect:
    exit_code: 0
  on_failure:
    collect: [...]
    hints: {...}
```

Step ids matter beyond documentation: they are what `--start-at` and `--only`
name, and what a brief's `start_at` / `only_steps` refer to. Renaming one breaks
every brief that resumes from it — which validation will catch, offline.

### Expectations

Default is `exit_code: 0`. Available keys:

```yaml
expect:
  exit_code: 0
  any_exit_code: true            # accept whatever comes back
  stdout_contains: PREFLIGHT_OK
  stdout_not_contains: FAILED
  stdout_regex: 'Version\s+2\.\d+'
```

Expectations are templated, so `stdout_contains: '{{package}}'` works — useful
for "confirm the output mentions what we just installed".

A typo in an expectation key is rejected at load time rather than silently
ignored.

### Failure diagnostics — the part that matters

This is what makes an agent able to fix things rather than just report them.

```yaml
on_failure:
  collect:
    - files:
        - 'C:\Windows\Temp\ac-install-*.log'
        - 'C:\Windows\Temp\MSI*.LOG'
      tail_lines: 120
    - eventlog:
        log: Application
        newest: 25
        level: error
    - command: Get-Service MyApp | Format-List
  hints:
    "1603": >-
      Generic MSI failure. Search the collected verbose log for
      "Return value 3" -- that marks the action that actually failed.
    "3010": The install SUCCEEDED but needs a reboot. Do not re-run it.
    "*": Read the collected log before retrying.
```

- **`files`** accepts globs and resolves to the **most recently written** match,
  which is how you find an installer log with a generated name.
- **`eventlog`** becomes `Get-WinEvent` on Windows and `journalctl`/syslog
  elsewhere.
- **`hints`** are keyed by exit code, with `"*"` as a catch-all. Quote numeric
  keys — YAML would otherwise make them integers.

Write hints for the person (or agent) who has to act at 2am. "Generic MSI
failure" alone is useless; "search the log for Return value 3" is not.

### Placeholders

`{{name}}` comes from, in increasing priority: host fields (`host_id`, `host`,
`user`, `kind`), the host's `vars`, parameter defaults, then the parameters
actually supplied.

Rendering is **strict**. An unresolved placeholder raises rather than rendering
empty — `Remove-Item {{path}}` quietly becoming `Remove-Item` is how you delete
the wrong thing.

### Gating

| Setting | Effect |
|---|---|
| `requires_permission: true` (default) | Needs the operator's approval |
| `requires_permission: false` | Runs freely — only for genuinely read-only work |
| `destructive: true` | Implies approval, and is called out in the refusal |

A step marked `destructive` makes the whole operation gated.

On top of that, `safety.py` classifies every rendered command independently. An
operation cannot opt out of the block-list — see
[design.md](../SECURITY.md#41-the-command-deny-list).

---

## Running it

```powershell
# 1. See exactly what would run. Connects to nothing.
uv run ac preview target1 install-package -p package=agent.msi

# 2. Same, but exercising the whole pipeline without executing.
uv run ac run target1 install-package -p package=agent.msi --dry-run

# 3. For real, once the operator has approved.
uv run ac run target1 install-package -p package=agent.msi --confirm

# 4. After fixing a failure, re-run only from where it stopped.
uv run ac run target1 install-package -p package=agent.msi --confirm --start-at install
```

`--start-at` matters. Re-running a whole operation from the top after a
mid-operation failure repeats work that already succeeded, and for a destructive
step that is sometimes actively harmful.

---

## The end-to-end summary

Every run produces a shareable Markdown report, whether it succeeded or failed —
especially when it failed. It is written for someone who was not watching: what
ran, where, whether it worked, and if not, the evidence and the next action.

```powershell
uv run ac run target1 install-package -p package=agent.msi --confirm --summary
```

It contains the result, host, route, timings, session and agent ids, the
parameters used, a per-step table, and on failure the output, the collected logs,
the hint, and the exact command to resume from.

Three ways to get it:

| Where | How |
|---|---|
| Printed | `ac run ... --summary` |
| On disk | `<audit dir>/<session_id>-NN-<operation_id>.md` — the path is in `summary_file` |
| In the result | the `summary` field, so an agent relays it verbatim rather than paraphrasing |

Secrets are scrubbed from it like everything else, so it is safe to paste into a
ticket or a chat.

---

## Restricting a session

```powershell
uv run ac connect target1 --ops install-package,windows-health
```

The session then refuses anything else, even operations the catalog would
otherwise permit on that host. Use it when handing a session to an agent for one
specific job.

---

## Checklist for a new operation

- [ ] `host_ids` or `tags` name real hosts
- [ ] Every `{{placeholder}}` is a declared param or a host var
- [ ] A preflight step fails *early* and cheaply, with a distinct exit code
- [ ] Destructive steps are marked `destructive: true`
- [ ] `on_failure.collect` gathers what someone would actually read
- [ ] `hints` name a concrete next action, not a restatement of the error
- [ ] A verification step confirms the change landed
- [ ] `ac preview` output reads correctly
- [ ] `ac run --dry-run` passes
