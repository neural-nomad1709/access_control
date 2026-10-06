# Installation

From nothing to a validated `ac doctor` on a new machine. Assumes no prior
knowledge of the tool.

Nothing is installed on the servers you will manage. Everything here happens on
the workstation you sit at.

---

## 1. Prerequisites

| Requirement | Minimum | Why |
|---|---|---|
| **Python** | 3.12 | `config.py` and friends use 3.12 typing syntax; `requires-python = ">=3.12"` |
| **[uv](https://docs.astral.sh/uv/)** | any recent | Dependency resolution and the `uv run ac` entry point |
| **An interactive terminal** | — | Passwords are typed here; there is no other way in |
| **Network path to your first bastion** | — | Usually the corporate VPN |
| **An SSH private key** (if a hop uses one) | OpenSSH format | Paramiko cannot read PuTTY `.ppk` — see [conversion](#putty-ppk-keys) |

### Platform support

| Platform | Status | Notes |
|---|---|---|
| **Windows 10/11** | Primary, fully supported | The only platform with the credential dialog, `mstsc` (`ac rdp`) and `cmdkey` staging |
| **Linux** | Supported for SSH work | No `ac rdp`; no Windows credential dialog — a TTY is required for prompting |
| **macOS** | Supported for SSH work | Same limits as Linux |

WinRM/PSRP targets work from any platform (pypsrp is pure Python), but the
`ntlm_provider: sspi` option is Windows-only; on other platforms use the default
`auto` (which resolves to the pure-Python provider for direct routes) or set
`python` explicitly.

### Optional client tools

| Tool | Needed for | Install |
|---|---|---|
| `mstsc.exe` | `ac rdp` | Built into Windows |
| `ssh` client | `ac shell` | Built into Windows 10+; `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0` if missing |
| `cmdkey` | `ac rdp --stage-credentials` | Built into Windows |
| PuTTYgen | Converting `.ppk` keys | Ships with PuTTY (`winget install PuTTY.PuTTY`) |

`ac doctor` reports which of these it can find.

---

## 2. Install uv

**Windows (PowerShell):**

```powershell
winget install --id=astral-sh.uv -e
# or:
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Linux / macOS:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Confirm:

```powershell
uv --version
```

---

## 3. Get the repository

```powershell
git clone <your-repo-url> access_control
cd access_control
```

If you were handed a folder rather than a clone, that is fine — nothing here
requires git. Note that `config/inventory.yaml` is **deliberately not
gitignored**: it holds topology and no secrets, and sharing it is the point.

---

## 4. Dependencies

```powershell
uv sync --extra dev
```

This creates `.venv/` and installs from the locked `uv.lock`.

### What gets installed

| Package | Purpose |
|---|---|
| `paramiko>=3.4` | SSH transport, `direct-tcpip` channels, SFTP |
| `pypsrp>=0.8` | PowerShell Remoting (WinRM) client |
| `pyyaml>=6.0` | Config parsing (`safe_load` only) |
| `typer>=0.12` | CLI |
| `rich>=13.0` | Terminal rendering |
| `pywin32>=306` | Windows credential dialog — **Windows only**, skipped elsewhere |
| `pytest`, `pytest-cov` | The `dev` extra: test suite |

`spnego` arrives transitively with `pypsrp` and provides the pure-Python NTLM
provider.

### Without uv

A plain venv works too, though `uv run` is what every example in the docs uses:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
ac doctor
```

---

## 5. Create your configuration

```powershell
copy config\inventory.example.yaml config\inventory.yaml
```

`config/operations.yaml` ships ready to use. If `inventory.yaml` is missing the
tool falls back to `inventory.example.yaml` so a fresh clone is not dead on
arrival, but you should create the real file.

Edit `config/inventory.yaml` to describe *your* machines. The minimum viable
inventory is one bastion and one target:

```yaml
logging:
  enabled: true
  retention_days: 30
  level: INFO

hops:
  bastion1:
    role: bastion
    kind: ssh
    username: youruser
    description: QA SSH bastion
    context: {environment: QA, datacenter: East, network_zone: Internal, owner: PlatformOps}
    auth:
      method: key+password          # password | key | key+password | agent
      key_file: ~/.ssh/id_rsa
    via:
      from: local                   # 'local' = this workstation
      hostname: bastion1.example.net
      port: 2222                    # mandatory — never defaulted
      protocol: ssh

hosts:
  linux-app01:
    role: target
    kind: linux
    username: appuser
    tags: [linux, qa]
    context: {environment: QA, datacenter: East, network_zone: Internal, owner: AppOps}
    auth: {method: password}
    via:
      from: bastion1                # address AS SEEN FROM bastion1
      hostname: 10.20.4.20
      port: 22
      protocol: ssh
```

Every field is documented in [CONFIGURATION.md](CONFIGURATION.md). The two rules
that catch people first:

- **Ports are mandatory** on every `via:` endpoint.
- **Addresses are as seen from `from:`**, not from your laptop.

---

## 6. Build steps

There are none for normal use — `uv run ac` runs from source.

To produce a wheel (hatchling, packages `src/access_control`):

```powershell
uv build
# dist/access_control-0.2.0-py3-none-any.whl
```

Installing that wheel puts an `ac` executable on `PATH`, but note that
`config_dir()` then resolves relative to the *installed* package location.
Set `AC_HOME` or `AC_CONFIG_DIR` to point at your config directory if you install
this way. Running from the repo with `uv run ac` avoids the question entirely and
is what every example assumes.

---

## 7. Validate the installation

```powershell
uv run ac doctor
```

This touches **no network**. It checks, and prints a row for each:

| Check | Passing looks like |
|---|---|
| `python` | Your interpreter version |
| `import paramiko / pypsrp / yaml / typer` | `installed` |
| `inventory.yaml` | The resolved path (a warning if it fell back to the example) |
| `config parse` | `N hosts, M operations`, plus any cross-file warnings |
| `key <hop>` | The key file exists and is not a `.ppk` |
| `route <host>` | The resolved chain for every configured host |
| `credential prompt` | `interactive terminal (preferred)` or `Windows credential dialog` |
| `mstsc (RDP)` / `ssh client` | Path, or `not found` |
| `audit log dir` / `session dir` | Where trails and descriptors will be written |
| `live sessions` | `none` on a fresh machine |

It exits non-zero and prints `N check(s) failed` if anything is wrong; otherwise
`Ready.`

### Then validate the configuration itself, still offline

```powershell
uv run ac hosts            # every target and whether its route resolves
uv run ac routes           # every declared leg, and your entry points
uv run ac routes <host>    # resolve one route, with per-hop context
uv run ac ops              # the operation catalogue and what gates each one
```

### Then validate reachability (this one uses the network)

```powershell
uv run ac probe <host>          # prompts for the bastion credential
uv run ac probe <host> --deep   # also asks a Windows jump server about the target
```

`probe` is read-only. The line to look for is `tcp forwarding: yes` on each
bastion — `NO` means `AllowTcpForwarding no` and no jump through that host is
possible until its owner changes it.

### Finally, a real session

```powershell
uv run ac connect <host>
# … prompts per hop; you land at a prompt on the host
uv run ac verify <host> --expect-hostname <ITS-REAL-NAME>    # in another terminal
uv run ac disconnect <host>
```

---

## 8. Run the test suite

```powershell
uv run pytest                                            # 340 tests, fully offline
uv run pytest -q tests/test_e2e.py                       # the two end-to-end loops
uv run pytest --cov=access_control --cov-report=term-missing
```

Every test runs offline — the SSH layer is exercised against a real Paramiko SSH
server started in-process, not a mock. See [guides/testing.md](guides/testing.md).

---

## 9. Common installation problems

### `config file not found: …/config/inventory.yaml`

You skipped step 5, and no `inventory.example.yaml` was found either. Copy the
example, or set `AC_CONFIG_DIR` to wherever your config actually lives.

### `import pywin32 …` / the credential dialog is unavailable

Expected on Linux and macOS — `pywin32` is a Windows-only dependency. Prompting
falls back to the terminal, which is the preferred path anyway. On Windows, if
`ac doctor` says `no way to prompt`, you are running in something that is not a
real terminal; run `ac connect` from a genuine console window.

### PuTTY `.ppk` keys

Paramiko cannot read PuTTY's format. `ac doctor` flags it before you ever attempt
a connection. Convert once:

```powershell
puttygen "C:\path\to\key.ppk" -O private-openssh -o "C:\path\to\key.pem"
```

Then point `auth.key_file` at the `.pem`.

### `inventory is invalid:` at startup

Validation is strict and reports **every** problem it can find in one pass, by
design: a misconfigured inventory should fail at load time, not halfway through a
patch run. Read the whole list, fix all of it, re-run `ac doctor`.

### `no route defined between requested target and available bastion`

Not a network problem — nothing was attempted. The target has no declared `via:`
edge reaching it. See
[guides/runbook.md](guides/runbook.md#error-no-route-defined-between-requested-target-and-available-bastion).

### Python 3.11 or older

`uv sync` will refuse. Install 3.12+:

```powershell
uv python install 3.12
```

### The repository is inside OneDrive (or another sync folder)

That is the case this project was built in, and it is handled: audit logs,
session descriptors and state are written to `%LOCALAPPDATA%\access_control\`,
**outside** the repo, so captured server output is never uploaded. Do not
override `logging.path` to point back inside the repository.

---

## 10. Uninstalling

```powershell
# remove the environment
rm -r .venv
# remove per-user state, logs and any live session descriptors
rm -r $env:LOCALAPPDATA\access_control
```

Nothing was installed on any server, no service was registered, and no scheduled
task was created. Removing the folder removes the tool.

---

## Next

| You want to | Read |
|---|---|
| Understand the daily loop | [guides/runbook.md](guides/runbook.md) |
| Know what every setting does | [CONFIGURATION.md](CONFIGURATION.md) |
| Add a host or an operation | [guides/operations-guide.md](guides/operations-guide.md) |
| Run it in production | [OPERATIONS.md](OPERATIONS.md) |
| Review the security posture | [SECURITY.md](SECURITY.md) |
