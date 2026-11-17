# access_control with AgentLighthouse

This part of the documentation covers running access_control **integrated with
[AgentLighthouse](https://github.com/neural-nomad1709/agentlighthouse)**, the
governance plane. Everything outside `docs/integration/` describes the
standalone product, which needs none of this.

| If you want… | Read |
|---|---|
| The standalone product (no AgentLighthouse) | [../../README.md](../../README.md), [../INSTALLATION.md](../INSTALLATION.md) |
| The integrated install and its commands | [§2](#2-commands) below |
| An agent reaching `ac` through the AgentLighthouse MCP proxy | [mcp-proxy-config.md](mcp-proxy-config.md) |
| One SIEM stream for both audit trails | [siem-combined-stream.md](siem-combined-stream.md) |
| What is still to be built | [§6](#6-plan) below |

---

## 1. What the integration is

There are two ways AgentLighthouse attaches to access_control:

| Integration point | What it does | Usable today from the command line |
|---|---|---|
| **MCP proxy** (`al mcp proxy -- uv run ac mcp <host>`) | The agent reaches `ac` only through AgentLighthouse, which pins the tool surface, applies per-identity policy, scans results and signs a receipt per call | **Yes**, see [mcp-proxy-config.md](mcp-proxy-config.md) |
| **Embedded gatekeeper** (`LighthouseGatekeeper` behind the `Gatekeeper` seam) | Inside `ac`: default-deny tool policy, out-of-band human approval, output scanning with taint, every audit action mirrored into a signed ledger | **No.** It is built and tested, but no `ac` command constructs it yet ([§6](#6-plan)) |

The seam is one interface, `Gatekeeper` (`src/access_control/gatekeeper.py`).
Its default, `NullGatekeeper`, changes nothing, which is why the standalone
product behaves exactly as if the integration did not exist.

---

## 2. Commands

The integrated mode has its own commands. None of them is shared with the
standalone ones, so the command you type tells you which mode you are in.

| | Standalone | Integrated with AgentLighthouse |
|---|---|---|
| Install | `uv sync --extra dev` | `uv sync --extra dev --extra lighthouse --group lighthouse-test` |
| Run the tool | `uv run ac …` | `uv run --extra lighthouse ac …` |
| Test suite | `uv run pytest` | `uv run --extra lighthouse --group lighthouse-test pytest` |
| AgentLighthouse CLIs | not installed | `uv run --extra lighthouse al …`, `uv run --extra lighthouse al-verify …` |

Until the embedded gatekeeper is wired into the CLI, `uv run --extra lighthouse
ac …` behaves the same as `uv run ac …`. What the integrated install adds today
is the `al` and `al-verify` commands and the integration tests.

### What the two flags add

| Flag | Installs | Import name | Used for |
|---|---|---|---|
| `--extra lighthouse` | `agentlighthouse-core`, `agentlighthouse-verify` | `al_core`, `al_verify` | `LighthouseGatekeeper`, the `al` MCP proxy, `al-verify` |
| `--group lighthouse-test` | `agentlighthouse-governance` | `al_governance` | Only the posture-attestation test. Never a runtime dependency |

### Switching back to standalone

`uv sync` installs exactly what it is asked for, so this removes the
AgentLighthouse packages:

```powershell
uv sync --extra dev
```

`uv run` on its own does **not** remove them. After an integrated install, a
plain `uv run pytest` still finds AgentLighthouse and runs the integration tests
too. Run the standalone `uv sync` first when you need to prove the standalone
product works.

### Verifying a receipt ledger

```powershell
uv run --extra lighthouse al-verify <data-dir>\ledger.jsonl --pubkey <public-key-file-or-hex>
```

`al-verify` checks the hash chain and every Ed25519 signature. Its only
dependency is `cryptography`, so an auditor can run it without access_control.

---

## 3. Where AgentLighthouse comes from

`pyproject.toml` pins all three packages to one release tag of the
AgentLighthouse repository (`[tool.uv.sources]`, git + `tag`), and `uv.lock`
records the exact commit. Current pin: **`v0.4.0`**.

- The first integrated install needs network access to GitHub.
- A local AgentLighthouse checkout is never used, so work in progress there
  cannot break access_control.
- `tool.uv.sources` is a uv feature. The integrated mode needs uv; the plain
  `pip install -e ".[dev]"` route in [INSTALLATION.md](../INSTALLATION.md) is
  standalone only.

### Moving to a newer AgentLighthouse release

Change the `tag` on all three source lines in `pyproject.toml`, then:

```powershell
uv lock
uv run --extra lighthouse --group lighthouse-test pytest
```

`tests/test_packaging_independence.py` fails if the three tags ever differ, or
if a source points at a path outside this repository.

### Package names

AgentLighthouse renamed its packages in 0.4.0. The import names and the `al`,
`al-verify` and `al-gov` commands did not change.

| Package (0.4.0 on) | Before 0.4.0 | Directory | Import name |
|---|---|---|---|
| `agentlighthouse-core` | `al-core` | `core/` | `al_core` |
| `agentlighthouse-verify` | `al-verify` | `verify/` | `al_verify` |
| `agentlighthouse-governance` | `al-governance` | `governance/` | `al_governance` |

The phase reports in [§7](#7-history) were written before the rename and use the
old names.

---

## 4. Tests that need the integration

These three files skip themselves in the standalone mode and run in the
integrated one:

| File | Tests | Covers |
|---|---:|---|
| `test_lighthouse_gatekeeper.py` | 28 | Audit actions mirrored into the signed, chained ledger; default-deny policy; held approvals across a restart; the engine end to end with the real gatekeeper |
| `test_mcp_acceptance.py` | 6 | The mediated agent path: descriptors pinned, per-identity policy, results scanned, a signed receipt per hop |
| `test_posture_attestation.py` | 4 | A posture attestation built from ac's receipts verifies with `al-verify`; tampering is detected |

Standalone: **516 passed, 3 skipped**. Integrated: **554 passed**. CI runs both
modes on Ubuntu and Windows (`.github/workflows/ci.yml`).

---

## 5. Configuration files

| File | Read by | Names |
|---|---|---|
| `config/tool-policy.yaml` | The embedded `LighthouseGatekeeper` | Catalogue steps (`<operation>.<step>`) and `ac_exec` |
| `config/mcp-tool-policy.yaml` | The `al mcp proxy` | The MCP tools (`ac_status`, `ac_run_operation`, …) |
| `config/al-mcp-proxy.yaml` | The `al mcp proxy` (`--config`) | Points AgentLighthouse at `mcp-tool-policy.yaml` |

The standalone product reads none of them.

---

## 6. Plan

What is left to make the integrated mode a working product rather than a
tested library:

1. **Switch the embedded gatekeeper on from the CLI.** `ac connect` builds a
   `LighthouseGatekeeper` and hands it to `build_session`. **Open decision:** a
   flag on `ac connect`, or a setting in the config file.
2. **Operator settings for it.** The data directory (ledger and signing key),
   the tool policy path and the org name.
3. **An end-to-end test through the CLI.** Drive `ac` in governed mode and
   verify the resulting ledger with `al-verify`.
4. **Developing against a local AgentLighthouse checkout.** A documented, tested
   command for trying unreleased AgentLighthouse work without editing the pin.

---

## 7. History

The integration was built in phases. These reports record what each phase
found and decided; they are not current instructions.

| Report | Phase |
|---|---|
| [00-context.md](00-context.md) | Phase R: context load, and the original packaging finding |
| [01-phase-0-report.md](01-phase-0-report.md) | Phase 0: hygiene |
| [02-phase-al-0-report.md](02-phase-al-0-report.md) | Phase AL-0: AgentLighthouse pre-work |
| [03-phase-1-report.md](03-phase-1-report.md) | Phase 1: evidence (the Gatekeeper seam and the signed ledger) |
| [04-phase-2-report.md](04-phase-2-report.md) | Phase 2: enforcement |
| [05-phase-3-report.md](05-phase-3-report.md) | Phase 3: the mediated agent path |
| [06-phase-4-report.md](06-phase-4-report.md) | Phase 4: governance |

The last commit before any of this work is tagged
`pre-agentlighthouse-integration`.
