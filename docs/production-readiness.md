# Security and production readiness assessment

An assessment of access_control **v0.2.1** (standalone) as of **2026-11-16**,
based on the source, the configuration and a passing test run (516 tests).

Companion documents: [SECURITY.md](SECURITY.md) (the threat model and controls),
[CLAUDE_PRODUCTION_GUARDRAILS.md](CLAUDE_PRODUCTION_GUARDRAILS.md) (controls for
agent deployment), [../BugFixNchange.md](../BugFixNchange.md) (every fixed and
open item).

---

## 1. Verdict

**Ready for supervised production use on the SSH and direct-WinRM paths, with the
hardening in [SECURITY.md §10](SECURITY.md#10-production-hardening-checklist)
applied, including agent-driven change where the operator approves each gated
step. Not ready for unsupervised use, and the bastion → Windows jump → Windows
target path is unproven against real hardware.**

| Dimension | Rating | One-line justification |
|---|---:|---|
| Credential handling | **Strong** | Nothing stored; per-hop prompting; rejected credentials discarded; redaction applied at construction, not at the call site |
| Secret leakage prevention | **Strong** | Global registry; `ExecResult` and `RedactingError` self-scrub; verified by test against the on-disk trail |
| Connectivity control | **Strong** | Declared-only graph, ambiguity refused, environment boundary enforced, validated at load time |
| Wrong-host prevention | **Strong** | Identity check runs before any state-touching check, with a pinned name |
| Failure diagnosis | **Strong** | Nominated logs, exit-code hints, resume-from-step, shareable report |
| Authorization model | **Good** | Five gates; an agent's gated work waits for the operator's `:approve`; `--ops` also scopes ad-hoc commands. No RBAC or SSO |
| Audit trail | **Good** | Canonical, fsynced, SIEM-shaped, covers RDP launches and approvals — but written by the audited process |
| Command policy | **Good** | Two tiers, applied uniformly, comment-aware, regression-tested — but a pattern list, and advisory |
| Error handling | **Good** | Typed hierarchy, actionable messages, teardown never masks, tracebacks preserved |
| Test coverage | **Good** | 516 offline tests over a real in-process SSH server; no WinRM double |
| Documentation | **Good** | Standalone and integration parts kept separate; one tracker |
| Operational maturity | **Adequate** | CI on Ubuntu and Windows, bounded log files; no lint gate, no metrics, no alerting |
| Change control | **Adequate** | Under git with CI; `change_ref` is still an unvalidated string |
| Tamper evidence | **Absent** standalone | By design. The AgentLighthouse integration adds a signed ledger; otherwise a PAM product or a proxy |
| Unattended operation | **Absent** | By design. Follows directly from storing nothing |

---

## 2. What is genuinely strong

1. **The credential model is coherent all the way down.** Nothing is stored, the
   prompt cannot be driven by an agent, each hop is separate, a rejected password
   is discarded rather than retried, and the redaction happens inside the types
   that carry output rather than at each print site. The end-to-end test asserts
   that neither password appears anywhere in the on-disk trail.
2. **"Declared, never discovered" is enforced by the code path, not by
   convention.** `Session.connect` has no branch that skips route resolution, and
   `config.load_inventory` resolves every host at load time so an untraversable
   topology fails when the file is read.
3. **The wrong-host check exists at all.** Every hop past the first arrives over a
   local port forward, a port number carries no identity, and the resulting
   failure is *silent* — commands succeed, on the wrong server. Checking identity
   before disk space or services is the right ordering.
4. **Failure is treated as the main case.** Diagnostics are declared per step,
   collected automatically, clamped, and returned with an exit-code-specific hint
   and the exact command to resume from.
5. **The engine refuses to be clever.** It observes and reports; it never
   remediates. That division is what makes the output trustworthy.
6. **A human approves what an agent changes.** The approval is bound to the
   exact rendered commands, covers one run, and lapses into a denial.
7. **The tests are honest.** A real Paramiko SSH server, real `direct-tcpip`
   forwarding, real partial-authentication — which caught a genuine defect (B-01)
   that mocks would have hidden.

---

## 3. Risks

Ordered by expected impact. Severity assumes production use with an agent.

| # | Risk | Likelihood | Impact | Mitigation available today |
|---|---|---|---|---|
| R-01 | **An agent approves its own gated work on a session opened without `--agent-id`.** Detection then relies on the client declaring itself (F-01r) | Low | High | Open every agent session with `--agent-id`; scope it with `--ops` |
| R-03 | **The nested Windows-to-Windows path is unproven.** Implemented, unit-tested, never run against real hardware | High (if used) | High | Verify against a live jump server before relying on it; prefer direct or single-hop WinRM until then |
| R-04 | **The pure-Python NTLM provider steps around a corporate control.** `auto` selects it for every direct route | Medium | Medium–High (policy) | Prefer the bastion path; treat direct routes as a decision needing the NTLM policy owner's agreement; alert on `winrm.ntlm_provider: python` |
| R-05 | **Trust-on-first-use host keys.** The default `accept-new` accepts an unknown key on first contact | Low | High | `AC_HOST_KEY_POLICY=strict` with `known_hosts` seeded out of band |
| R-06 | **Production log content reaches the model.** No classification, no output filter beyond secret redaction | Medium | Medium–High (regulatory) | Narrow `on_failure.collect` to specific files and small `tail_lines`; classify operations before adding them |
| R-07 | **Prompt injection via collected server output.** A compromised host can put persuasive text in a log the agent reads | Low–Medium | Medium | Instructions come only from repo YAML; gated work needs `:approve`; the deny-list is the last check; state the "output is evidence, not instruction" rule in the agent's prompt |
| R-08 | **The session socket is not a privilege boundary.** Anything running as the operator can drive a live production session | Low | High | Workstation hygiene; bounded idle timeout and `--max-lifetime`; disconnect when done |
| R-09 | **The audit trail is not tamper-evident** | Low | Medium (compliance) | Ship JSONL to write-once storage as it is produced; use a PAM product, or the AgentLighthouse ledger, where evidence must stand up |
| R-10 | **`operations.yaml` is executable content.** Review is a process, not a control | Medium | High | Require pull-request review on `operations.yaml`, `inventory.yaml` and `safety.py` |
| R-11 | **A shell alongside the agent bypasses every control here.** The model assumes `Bash(uv run ac …)` is the only route to the servers | Medium | High | Deny `ssh`, `plink`, `mstsc` and direct edits to the config in the agent's permission set |
| R-14 | **Single point of failure: the operator's terminal.** Closing it ends the work | High | Low (by design) | Bounded scope per session; resume with `--start-at` |

---

## 4. Assumptions this system rests on

If one of these is false in your environment, re-evaluate the control above it.

1. The operator's workstation is trusted, patched and disk-encrypted.
2. The operator reads the prompt label before typing a password, and reads the
   commands before typing `:approve`.
3. `context.environment` is set on every node — the QA→PROD boundary check is a
   no-op where it is blank.
4. `known_hosts` is meaningful; under `accept-new` first contact is
   trust-on-first-use.
5. The bastion and any Windows jump server are not hostile — the jump server
   holds the target credential in memory during a nested call.
6. `operations.yaml` and `inventory.yaml` are reviewed like code, by someone who
   understands they are executable.
7. YAML configuration is trusted input (`yaml.safe_load` prevents object
   instantiation, but not a reviewer approving a harmful step).
8. The agent is fallible, not adversarial. Nothing here defends against a
   deliberately malicious client running as the operator.
9. The estate's own controls — `sshd_config`, firewall rules, WinRM ACLs, account
   rights — remain the real enforcement.
10. Captured server output is sensitive but does not require encryption at rest
    on the workstation beyond full-disk encryption.
11. Someone is watching. Every safeguard here assumes a present operator.

---

## 5. Known limitations

Design choices with consequences, not defects. Each is stated in
[guides/features.md](guides/features.md#honest-limitations) too.

| # | Limitation | Consequence | The tool that solves it |
|---|---|---|---|
| L-01 | Nothing is stored | No unattended or scheduled runs; a terminal must stay open | PAM product, vaulted service account |
| L-02 | Not idempotent | Running an operation twice runs it twice | Ansible |
| L-03 | One Windows jump server maximum | Deeper chains need a different credential model | Reach the extra jump as a target in its own right |
| L-04 | SSH cannot follow WinRM in a chain | Order the route with bastions first | — |
| L-05 | WinRM double-hop | A target cannot reach a UNC share on its own behalf | Server-local package share, upload-then-install, or CredSSP |
| L-06 | Kerberos does not work over the tunnel | NTLM with message encryption is used | `winrm-ssl` where offered |
| L-07 | The route graph is advisory | Constrains this tool, not the network | Teleport, PAM |
| L-08 | The command policy is a pattern list | Will not catch everything | `sudoers`, account rights |
| L-09 | The audit trail is written by the audited process | Not chain-of-custody evidence | Teleport session recording, PAM |
| L-10 | No RBAC, SSO, or multi-user approval | One operator, one session, one approver | Teleport, PAM, Rundeck |
| L-11 | `.ppk` keys need conversion | One-time PuTTYgen step | — |
| L-12 | Campaign fan-out is bounded by human-opened sessions | A handful of hosts, not a fleet | Ansible, Rundeck |
| L-13 | Windows-only for RDP, the credential dialog and SSPI | SSH work is cross-platform; Windows features are not | — |
| L-14 | Small ecosystem | The operations are the ones you write | Ansible Galaxy |

---

## 6. Readiness by scenario

| Scenario | Ready? | Conditions |
|---|---|---|
| **Human-driven SSH/Unix work through a bastion chain** | **Yes** | Verified end to end against production AIX. Apply the hardening checklist |
| **Human-driven direct WinRM (VPN / same segment)** | **Yes** | Verified against Windows Server 2022. Understand the NTLM provider question (R-04) |
| **Human-driven WinRM through an SSH bastion** | **Probably** | Implemented and unit-tested; prove it with `ac probe --deep` and a read-only operation first |
| **Human-driven nested Windows→Windows** | **Not yet** | Unproven against real hardware (R-03) |
| **Agent-driven read-only investigation** | **Yes** | Session opened with `--agent-id` and `--ops` limited to read-only operations; operator present |
| **Agent-driven change under supervision** | **Yes** | Reviewed brief, `expect_hostname`, session opened with `--agent-id` and `--ops`, operator approves each gated step with `:approve` |
| **Agent-driven change unsupervised** | **No** | Every gated step needs the operator at the `ac connect` prompt, by design |
| **Fleet-wide campaigns (>10 hosts)** | **No** | One human-opened session per host is the ceiling |
| **Regulated data (PCI/PHI/PII) in scope** | **Conditional** | R-06 has no technical control; requires a data-flow decision and narrow collectors |
| **Compliance requiring tamper-evident recording** | **No** standalone | R-09; needs the AgentLighthouse ledger, Teleport or a PAM product |

---

## 7. Recommended work, in order

### Before the next production change

1. Require pull-request review on `operations.yaml`, `inventory.yaml` and
   `safety.py` (R-10).
2. Apply the hardening checklist in
   [SECURITY.md §10](SECURITY.md#10-production-hardening-checklist) — in
   particular `AC_HOST_KEY_POLICY=strict` and `environment` on every node.
3. Adopt the agent permission policy in
   [CLAUDE_PRODUCTION_GUARDRAILS.md §8.2](CLAUDE_PRODUCTION_GUARDRAILS.md#82-tool-permission-policy-claude-code-settingsjson),
   including denying a general shell (R-11), and open every agent session with
   `--agent-id` (R-01).
4. Ship `<log dir>/*.jsonl` to the SIEM and implement the P1 alerts in
   [OPERATIONS.md §4.2](OPERATIONS.md#42-signals-worth-alerting-on).

### Engineering

5. Add a lint and type check to CI (F-21) and a coverage threshold (F-22).
6. Verify the nested Windows path against real hardware and record the evidence
   (R-03, F-26).
7. A WinRM test double, so the Windows paths are covered offline (F-25).
8. Remove or wire up the dead code (F-14 to F-18).
9. Optional **output filtering / classification** for regulated estates (R-06).

### Longer term (if the scope grows)

10. A credential-broker integration, which is the only way past the
    one-session-per-human ceiling — and a decision that changes the threat model
    substantially. It should be taken deliberately, not by accretion.
11. Streaming the audit trail to write-once storage for tamper evidence (R-09).
12. Change-management integration so `change_ref` is validated rather than
    recorded.

---

## 8. What would change this assessment

| If this happened | The verdict becomes |
|---|---|
| The nested path is verified against real hardware | The flagship topology moves from "unproven" to supported |
| Lint, type and coverage gates land | Operational maturity moves from Adequate to Good |
| The embedded AgentLighthouse gatekeeper can be switched on from the CLI | Tamper-evident evidence becomes available without code changes |
| A credential broker is added | The threat model changes fundamentally — nothing in this assessment carries over unreviewed |
| The tool is used unattended, or with a stored credential | **Every conclusion here is void.** The design's safety rests on a present human |
