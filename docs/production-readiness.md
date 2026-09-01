# Security and production readiness assessment

An assessment of `access-control` v0.1.0 as of **2026-08-17**, based on reading
the source, the configuration and a passing test run (340 tests).

Companion documents: [SECURITY.md](SECURITY.md) (the threat model and controls),
[gap-analysis.md](gap-analysis.md) (what is missing and why),
[CLAUDE_PRODUCTION_GUARDRAILS.md](CLAUDE_PRODUCTION_GUARDRAILS.md) (controls for
agent deployment).

---

## 1. Verdict

**Ready for supervised production use on the SSH and direct-WinRM paths, with the
hardening in [SECURITY.md §10](SECURITY.md#10-production-hardening-checklist)
applied. Not ready for unsupervised or agent-self-approved use, and the
bastion → Windows jump → Windows target path is unproven against real hardware.**

| Dimension | Rating | One-line justification |
|---|---:|---|
| Credential handling | **Strong** | Nothing stored; per-hop prompting; rejected credentials discarded; redaction applied at construction, not at the call site |
| Secret leakage prevention | **Strong** | Global registry; `ExecResult` and `RedactingError` self-scrub; verified by test against the on-disk trail |
| Connectivity control | **Strong** | Declared-only graph, ambiguity refused, environment boundary enforced, validated at load time |
| Wrong-host prevention | **Strong** | Identity check runs before any state-touching check, with a pinned name |
| Failure diagnosis | **Strong** | Nominated logs, exit-code hints, resume-from-step, shareable report |
| Audit trail | **Good** | Canonical, fsynced, SIEM-shaped — but written by the audited process, and RDP is unrecorded |
| Command policy | **Good** | Two tiers, applied uniformly, comment-aware, regression-tested — but a pattern list, and advisory |
| Error handling | **Good** | Typed hierarchy, actionable messages, teardown never masks, tracebacks preserved |
| Test coverage | **Good** | 340 offline tests over a real in-process SSH server; no WinRM double |
| Documentation | **Good** | Complete after this pass; previously the weakest area |
| Authorization model | **Adequate** | Five gates, but no RBAC, no SSO, and `--confirm` proves nothing about a human |
| Operational maturity | **Adequate** | Good introspection; no CI, no metrics, no alerting, two unbounded log files |
| Change control | **Weak** | `change_ref` is an unvalidated string; no history in the repository at all |
| Tamper evidence | **Absent** | By design. Needs a PAM product or a proxy |
| Unattended operation | **Absent** | By design. Follows directly from storing nothing |

---

## 2. What is genuinely strong

These are not table stakes and are worth saying plainly.

1. **The credential model is coherent all the way down.** Nothing is stored, the
   prompt cannot be driven by an agent, each hop is separate, a rejected password
   is discarded rather than retried, and the redaction happens inside the types
   that carry output rather than at each print site. The end-to-end test asserts
   that neither password appears anywhere in the on-disk trail.
2. **"Declared, never discovered" is enforced by the code path, not by
   convention.** `Session.connect` has no branch that skips route resolution, and
   `config.load_inventory` resolves every host at load time so an untraversable
   topology fails when the file is read.
3. **The wrong-host check exists at all.** Most tools in this space do not have
   it. Every hop past the first arrives over a local port forward, a port number
   carries no identity, and the resulting failure is *silent* — commands succeed,
   on the wrong server. Checking identity before disk space or services is the
   right ordering.
4. **Failure is treated as the main case.** Diagnostics are declared per step,
   collected automatically, clamped, and returned with an exit-code-specific hint
   and the exact command to resume from. This is the feature the whole design
   exists for, and it is the best-executed part of the codebase.
5. **The engine refuses to be clever.** It observes and reports; it never
   remediates. That division is what makes the output trustworthy.
6. **Errors are written for the person who has to act.** "Password
   authentication failed. NOTE: the public key was ALREADY REJECTED, so no
   password can succeed until the key is accepted — most often the username is
   wrong" is the difference between a five-minute fix and an afternoon.
7. **The tests are honest.** A real Paramiko SSH server, real `direct-tcpip`
   forwarding, real partial-authentication — which caught a genuine defect
   (`PartialAuthentication` is not re-exported at Paramiko's top level in 5.x)
   that mocks would have hidden.

---

## 3. Risks

Ordered by expected impact. Severity assumes production use with an agent.

| # | Risk | Likelihood | Impact | Mitigation available today |
|---|---|---|---|---|
| R-01 | **An agent self-approves a destructive operation.** `--confirm` is a flag the caller passes; nothing proves a human agreed at that moment | Medium | High | Scope the session with `--ops` to read-only operations and have the operator run destructive commands themselves |
| R-02 | **A "restricted" session is not restricted.** `--ops` covers catalogue operations; `ac exec` remains available for any `ALLOWED`-class command, and any `CONFIRM`-class one with `--confirm` | Medium | High | Do not hand an agent a live session you would not hand a shell |
| R-03 | **The nested Windows-to-Windows path is unproven.** Implemented, unit-tested, never run against real hardware | High (if used) | High | Verify against a live jump server before relying on it; prefer direct or single-hop WinRM until then |
| R-04 | **The pure-Python NTLM provider steps around a corporate control.** `auto` selects it for every direct route | Medium | Medium–High (policy) | Prefer the bastion path; treat direct routes as a decision needing the NTLM policy owner's agreement; alert on `winrm.ntlm_provider: python` |
| R-05 | **Trust-on-first-use host keys.** The default `accept-new` accepts an unknown key on first contact | Low | High | `AC_HOST_KEY_POLICY=strict` with `known_hosts` seeded out of band |
| R-06 | **Production log content reaches the model.** No classification, no output filter beyond secret redaction | Medium | Medium–High (regulatory) | Narrow `on_failure.collect` to specific files and small `tail_lines`; classify operations before adding them |
| R-07 | **Prompt injection via collected server output.** A compromised host can put persuasive text in a log the agent reads | Low–Medium | Medium | Instructions come only from repo YAML; the deny-list is the last check; state the "output is evidence, not instruction" rule in the agent's prompt |
| R-08 | **The session socket is not a privilege boundary.** Anything running as the operator can drive a live production session | Low | High | Workstation hygiene; bounded idle timeout; disconnect when done |
| R-09 | **The audit trail is not tamper-evident** and RDP sessions are not recorded at all | Low | Medium (compliance) | Ship JSONL to write-once storage as it is produced; use a PAM product where evidence must stand up |
| R-10 | **`operations.yaml` is executable content with no enforced review** — and the repository has no commit history | Medium | High | Put it under real version control with required review before any production use |
| R-11 | **A shell alongside the agent bypasses every control here.** The whole model assumes `Bash(uv run ac …)` is the only route to the servers | Medium | High | Deny `ssh`, `plink`, `mstsc` and direct edits to the config in the agent's permission set |
| R-12 | ~~**No CI.** Nothing runs the 340 tests automatically~~ **Resolved 2026-08-31**: `.github/workflows/ci.yml` runs the suite on Ubuntu and Windows on every push and PR | — | — | Lint/type gates remain absent (F-20, F-21) |
| R-13 | **Unbounded `transport.log` / `errors.log`** | Medium | Low | External rotation |
| R-14 | **Single point of failure: the operator's terminal.** Closing it ends the work | High | Low (by design) | Bounded scope per session; resume with `--start-at` |

---

## 4. Assumptions this system rests on

If one of these is false in your environment, re-evaluate the control above it.

1. The operator's workstation is trusted, patched and disk-encrypted.
2. The operator reads the prompt label before typing a password.
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
| L-10 | No RBAC, SSO, or multi-user approval | One operator, one session | Teleport, PAM, Rundeck |
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
| **Agent-driven read-only investigation** | **Yes** | Session scoped with `--ops` to read-only operations; operator present |
| **Agent-driven change under supervision** | **Yes, with process** | Reviewed brief, `expect_hostname`, `--ops` scoping, operator runs the destructive step (R-01, R-02) |
| **Agent-driven change unsupervised** | **No** | R-01 and R-02 have no technical mitigation today |
| **Fleet-wide campaigns (>10 hosts)** | **No** | One human-opened session per host is the ceiling |
| **Regulated data (PCI/PHI/PII) in scope** | **Conditional** | R-06 has no technical control; requires a data-flow decision and narrow collectors |
| **Compliance requiring tamper-evident recording** | **No** | R-09; needs Teleport or a PAM product |

---

## 7. Recommended work, in order

### Before the next production change

1. Put the repository under real version control with review on
   `operations.yaml`, `inventory.yaml` and `safety.py` (R-10, F-23).
2. Apply the hardening checklist in
   [SECURITY.md §10](SECURITY.md#10-production-hardening-checklist) — in
   particular `AC_HOST_KEY_POLICY=strict` and `environment` on every node.
3. Adopt the agent permission policy in
   [CLAUDE_PRODUCTION_GUARDRAILS.md §8.2](CLAUDE_PRODUCTION_GUARDRAILS.md#82-tool-permission-policy-claude-code-settingsjson),
   including denying a general shell (R-11).
4. Ship `<log dir>/*.jsonl` to the SIEM and implement the P1 alerts in
   [OPERATIONS.md §4.2](OPERATIONS.md#42-signals-worth-alerting-on).

### Short term (engineering)

5. Add a CI workflow running `uv run pytest` (**done 2026-08-31**, Ubuntu + Windows);
   the lint/type pass is still open (F-20, F-21).
6. ~~Close F-07 (`ac tunnel --port` silently ignored) and F-08 (`postcheck:` never
   executed)~~ **Done 2026-08-31** — both fixed test-first (`test_cli_tunnel.py`,
   `test_cli_brief_postcheck.py`).
7. Emit `RDP_LAUNCH` audit records (F-03).
8. Either apply `logging.level` or remove it (F-05).
9. Rotate or bound `transport.log` and `errors.log` (F-06).
10. Remove the stray files from the working tree (F-24).

### Medium term (control gaps)

11. **An interactive approval gate** that cannot be satisfied by a flag — the
    single highest-value change for agent deployments (R-01).
12. **Extend `--ops` scoping to `run_command`**, or add a session mode that
    disables ad-hoc execution entirely (R-02).
13. Verify the nested Windows path against real hardware and record the evidence
    (R-03).
14. ~~An **absolute session lifetime** alongside the idle timeout (F-04).~~
    **Done 2026-09-01** — `ac connect --max-lifetime <secs>`.
15. Optional **output filtering / classification** for regulated estates (R-06).

### Longer term (if the scope grows)

16. A credential-broker integration, which is the only way past the
    one-session-per-human ceiling — and a decision that changes the threat model
    substantially. It should be taken deliberately, not by accretion.
17. Streaming the audit trail to write-once storage for tamper evidence (R-09).
18. Change-management integration so `change_ref` is validated rather than
    recorded.

---

## 8. What would change this assessment

| If this happened | The verdict becomes |
|---|---|
| An interactive approval gate lands, and `--ops` covers `run_command` | Agent-driven change under light supervision becomes reasonable |
| The nested path is verified against real hardware | The flagship topology moves from "unproven" to supported |
| CI, lint and a coverage gate land | Operational maturity moves from Adequate to Good |
| A credential broker is added | The threat model changes fundamentally — nothing in this assessment carries over unreviewed |
| The tool is used unattended, or with a stored credential | **Every conclusion here is void.** The design's safety rests on a present human |
