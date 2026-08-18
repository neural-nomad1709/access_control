# Documentation map

Start with the row that matches what you are trying to do.

| I want to… | Read |
|---|---|
| **Understand what this is in five minutes** | [../README.md](../README.md) |
| **Install it on a new machine** | [INSTALLATION.md](INSTALLATION.md) |
| **Use it for the first time** | [guides/runbook.md](guides/runbook.md#part-1--running-it-step-by-step) |
| **Fix something that is broken right now** | [guides/runbook.md](guides/runbook.md#part-2--troubleshooting-by-symptom) |
| **Decide whether this is the right tool at all** | [guides/features.md](guides/features.md#when-to-use-something-else) |
| **Know what every setting does** | [CONFIGURATION.md](CONFIGURATION.md) |
| **Add a host, or write an operation** | [guides/operations-guide.md](guides/operations-guide.md) |
| **Tell the agent what to do tonight** | [guides/instructions-guide.md](guides/instructions-guide.md) |
| **Run it in production, monitor it, upgrade it** | [OPERATIONS.md](OPERATIONS.md) |
| **Review the security posture** | [SECURITY.md](SECURITY.md) |
| **Deploy Claude against production safely** | [CLAUDE_PRODUCTION_GUARDRAILS.md](CLAUDE_PRODUCTION_GUARDRAILS.md) |
| **Understand how it is built** | [ARCHITECTURE.md](ARCHITECTURE.md) |
| **Change the code** | [implementation/README.md](implementation/README.md) |
| **Know the current state and what is missing** | [../STATUS.md](../STATUS.md), [gap-analysis.md](gap-analysis.md), [production-readiness.md](production-readiness.md) |

---

## By audience

### First-time user

1. [../README.md](../README.md) — what the tool is and why it works this way
2. [INSTALLATION.md](INSTALLATION.md) — prerequisites through `ac doctor`
3. [guides/runbook.md](guides/runbook.md) — Part 1 walks the whole loop
4. [guides/instructions-guide.md](guides/instructions-guide.md) — writing a task
   brief

### Developer

1. [ARCHITECTURE.md](ARCHITECTURE.md) — components, flows, boundaries
2. [implementation/README.md](implementation/README.md) — module contracts and
   conventions
3. [implementation/cli-reference.md](implementation/cli-reference.md) — every
   command and flag
4. [implementation/session-protocol.md](implementation/session-protocol.md) — the
   loopback wire protocol
5. [guides/testing.md](guides/testing.md) — how it is tested and what is not
   covered

### Administrator / operator

1. [CONFIGURATION.md](CONFIGURATION.md) — every setting, default and env var
2. [guides/operations-guide.md](guides/operations-guide.md) — adding hosts and
   operations
3. [OPERATIONS.md](OPERATIONS.md) — production use, monitoring, backup, upgrades
4. [guides/runbook.md](guides/runbook.md#part-2--troubleshooting-by-symptom) —
   troubleshooting

### Security reviewer

1. [SECURITY.md](SECURITY.md) — threat model, controls, assumptions, hardening,
   incident response
2. [ARCHITECTURE.md](ARCHITECTURE.md#11-trust-zones-and-security-boundaries) —
   trust zones
3. [implementation/audit-events.md](implementation/audit-events.md) — what is
   recorded
4. [CLAUDE_PRODUCTION_GUARDRAILS.md](CLAUDE_PRODUCTION_GUARDRAILS.md) — agent
   deployment controls, marked BUILT / CONFIG / GAP
5. [production-readiness.md](production-readiness.md) — the assessment, with
   risks and limitations

---

## Everything in this tree

```
docs/
  README.md                        this file
  ARCHITECTURE.md                  components, data flows, auth/authz, trust zones
  INSTALLATION.md                  prerequisites → validated install
  CONFIGURATION.md                 every setting, default and environment variable
  OPERATIONS.md                    dev, production, monitoring, backup, upgrades
  SECURITY.md                      threat model, controls, hardening, IR
  CLAUDE_PRODUCTION_GUARDRAILS.md  deploying an agent against production
  gap-analysis.md                  documentation and functionality gaps
  production-readiness.md          readiness assessment, risks, assumptions, limits
  guides/
    runbook.md                     step-by-step, then troubleshooting by symptom
    operations-guide.md            adding a host, writing an operation
    instructions-guide.md          task briefs, campaigns, rules for the agent
    features.md                    every feature, and how it compares
    testing.md                     test strategy, the two end-to-end loops
  implementation/
    README.md                      module contracts, conventions, extension points
    cli-reference.md               every command, flag and exit code
    audit-events.md                every audit record and its fields
    session-protocol.md            the loopback wire protocol
  reports/
    README.md                      what these are, and what they are not
    axway-session-error-report.md  connectivity/session findings, Axway CVT
    axway-app01-log-error-report.md application log findings, app-stg01
```

Outside `docs/`:

| File | Purpose |
|---|---|
| [../README.md](../README.md) | Project overview and quick start |
| [../STATUS.md](../STATUS.md) | Current state of the build and what is next |
| [../BugFixNchange.md](../BugFixNchange.md) | Bugs fixed, and what is still open |
| [../config/inventory.example.yaml](../config/inventory.example.yaml) | Annotated inventory template |
| [../config/operations.yaml](../config/operations.yaml) | The shipped operation catalogue |
| [../config/briefs/TEMPLATE.yaml](../config/briefs/TEMPLATE.yaml) | Annotated task-brief template |

---

## Conventions used throughout

| Term | Meaning |
|---|---|
| **hop** | A machine on the way to a target (bastion, jump server) |
| **host / target** | A final machine operations run against |
| **node** | Either of the above |
| **leg / edge** | One declared step from a source to a target, with its address and port |
| **route** | The resolved chain of legs from `local` to a target |
| **channel** | How commands are carried on the final leg: `ssh`, `winrm`, `nested-winrm` |
| **session** | One live authenticated path, held in the `ac connect` process |
| **degraded / fallback** | A session held at a hop because the target leg failed |
| **operation** | A catalogued, reusable capability with steps |
| **step** | One command inside an operation, with an expectation |
| **brief** | The instruction document for one job on one host |
| **campaign** | A fan-out of one brief across several hosts' live sessions |
| **gated** | Requires the operator's explicit `--confirm` |
| **declared, never discovered** | Connectivity comes only from config; nothing is probed or guessed |
