# Audit event reference

Every record the tool writes, what triggers it, and which fields it carries.

Location: `<log dir>/<trace_id>.jsonl`, one JSON object per line, flushed and
`fsync`ed immediately so an abrupt termination still leaves a complete trail. A
readable `<trace_id>.md` companion is written when the session closes.

Read them with `ac audit <session-id>` (raw) or `ac timeline <session-id>`
(ordered actions with durations).

---

## Record shape

Every record carries these, added by `AuditLog.emit`:

| Field | Type | Notes |
|---|---|---|
| `timestamp` | ISO-8601 UTC, millisecond precision | Canonical spelling for SIEM ingestion |
| `seq` | int | Monotonic within the session, from 1 |
| `agentId` | string | `AGT-<date>-<seq>`, or whatever `AC_AGENT_ID` says |
| `sessionId` | string | `SES-<seq>` |
| `event` | string | The event name (see below) |
| `host_id` | string | The session's target, when the log has one |

Records written through `AuditLog.action` add:

| Field | Type | Notes |
|---|---|---|
| `action` | string | One of the canonical action names |
| `source` | string | Node id, `local`, or `operator-prompt`. Defaults to `local` |
| `target` | string | Node id, or `<host>:<port>` for a tunnel |
| `result` | string | `SUCCESS` \| `FAILURE` \| `BLOCKED` \| `PENDING` |

**Every field value passes through `redact_obj` on the way in**, recursively, so a
registered secret cannot reach the file even if it was embedded in a command or
an error message.

`event` is derived from `action` by lower-casing and replacing `_` with `.`
(`SSH_CONNECT` → `ssh.connect`) unless the caller passes an explicit `event`, so
an existing event stream (`step.end`) can carry a canonical action without
emitting the record twice.

---

## Canonical actions

The sixteen names in `audit.ACTIONS`, used for filtering and correlation:

```
ROUTE_RESOLVE    SSH_CONNECT     WINRM_CONNECT   RDP_LAUNCH
TUNNEL_OPEN      AUTHENTICATE    COMMAND_EXECUTE SCRIPT_EXECUTE
FILE_UPLOAD      FILE_DOWNLOAD   LOG_COLLECT     PERMISSION_REQUEST
COMMAND_BLOCKED  SESSION_START   SESSION_END     ERROR
```

> Two action names are emitted that are **not** in that list: `PREFLIGHT` (from
> `daemon.do_preflight`) and `COMMAND` (from the operator prompt). They behave
> identically; the list is documentation, not an enum. Noted in
> [../gap-analysis.md](../gap-analysis.md).

---

## Events by lifecycle stage

### Session

| Event | Action | Emitted by | Key fields |
|---|---|---|---|
| `session.open` | `SESSION_START` | `Session.connect` | `route`, `hops[]` (id, role, source, address, channel, preestablished, context, domain), `allowed_operations[]`, `client_host`, `client_os`, `pid`, `detail` (= route) |
| `session.degraded` | — | `Session._degrade_to_hop` | `held_at`, `reason`, `note` |
| `session.recovered` | — | `Session.retry_target` | `host_id` |
| `session.idle_timeout` | — | `SessionServer._watchdog` | `idle_s` |
| `config.reload` | — | `SessionServer.do_reload` | `operations[]`, `added[]`, `removed[]`, `warnings[]` |
| `session.close` | `SESSION_END` | `AuditLog.close` | `status`, `detail` (= status), plus the whole summary: `elapsed_s`, `records`, `steps_run`, `steps_ok`, `steps_failed`, `errors`, `blocked`, `log_file` |

`status` values: `closed`, `idle-timeout`, `connect-failed`, `interrupted`,
`error`, `disconnected`. `result` is `SUCCESS` for `closed`/`idle-timeout`,
`FAILURE` otherwise.

### Connection

| Event | Action | Emitted by | Key fields |
|---|---|---|---|
| `hop.auth` | — | `transport/ssh._authenticate` | `hop_id`, `method` (`agent`\|`publickey`\|`password`\|`keyboard-interactive`), `username` |
| `hop.failed` | — | `transport/ssh.connect_hop` | `hop_id`, `stage` (`tcp`\|`handshake`), `error` |
| `host_key.new` | — | `transport/ssh.verify_host_key` | `host`, `port`, `fingerprint`, `policy` |
| `host_key.unreadable` | — | same | `path`, `error` |
| `ssh.connect` | `SSH_CONNECT` | `transport/ssh.connect_hop` | `hop_id`, `endpoint`, `channel`, `username`, `domain`, `auth_methods[]`, `host_key` (`known`\|`new`), `preestablished`, `context{}`, `duration_s` |
| `winrm.connect` | `WINRM_CONNECT` | `Session._connect_winrm` / `_connect_nested` | `hop_id`, `endpoint`, `channel` (`winrm`\|`nested-winrm`), `username`, `domain`, `context{}`, `duration_s` |
| `winrm.direct` | — | `Session._connect_winrm` | `hop_id`, `endpoint`, `note`. **Means no bastion was involved** |
| `winrm.ntlm_provider` | — | same | `hop_id`, `provider` (resolved), `configured` |
| `tunnel.open` | — | `Session._connect_winrm` | `hop_id` (the anchor), `target`, `local_port`, `purpose` |
| `tunnel.open` | `TUNNEL_OPEN` | `Session.open_tunnel` | `source`, `target`, `detail`, `local_port`, `purpose` (`rdp:`/`shell:`/`manual:`/`winrm:`) |
| `tunnel.preestablished` | — | `Session._connect_winrm` | `hop_id`, `endpoint`, `note` |
| `probe` | — | `probe._finish` | The entire probe report: `route`, `channel`, `nodes[]` with ports, verdicts and advice, `deep_result`, `blocked_at`, `forwarding_blocked_at`, `duration_s` |

### Execution

| Event | Action | Emitted by | Key fields |
|---|---|---|---|
| `preflight` | `PREFLIGHT` | `SessionServer.do_preflight` | `detail` (`N check(s), M blocker(s)`), `checks[]` (name, passed, detail, severity, duration_s, remedy) |
| `permission` | `PERMISSION_REQUEST` | `Engine._check_permission` | `operation_id`, `gated`, `confirmed`, `granted`. `result: BLOCKED` when refused |
| `operation.start` | — | `Engine.run_operation` | `operation_id`, `params{}`, `confirmed`, `dry_run`, `steps[]` |
| `step.start` | — | `Engine.run_step` | `operation_id`, `step_id`, `desc`, `shell`, `command` (redacted), `dry_run` |
| `step.end` | `SCRIPT_EXECUTE` | `Engine.run_step` | `operation_id`, `step_id`, `ok`, `exit_code`, `duration_s`, `expectation_reason`, `stdout_chars`, `collected`, `hint`, `detail` (`op/step`) |
| `command.blocked` | — | `Engine.run_step` | `operation_id`, `step_id`, `reason` |
| `command.blocked` | `COMMAND_BLOCKED` | `Engine.run_command` | `detail` (the command), `reason`, `result: BLOCKED` |
| `command.blocked` | `COMMAND_BLOCKED` | `operator_shell._execute` | `source: operator-prompt`, `command`, `result: BLOCKED` |
| `command` | `COMMAND_EXECUTE` | `Engine.run_command` | `detail` (the command), `shell`, `confirmed`, `exit_code`, `duration_s` |
| `command` | `COMMAND` | `operator_shell._report` | `source: operator-prompt`, `command`, `exit_code`, `degraded` |
| `operation.end` | — | `Engine.run_operation` | `operation_id`, `status`, `stopped_at`, `duration_s`, `steps_run`, `summary_file` |
| `collect` | `LOG_COLLECT` | `Engine.collect` | `detail` (`N source(s) after <step>`), `step_id`, `sources[]`, `exit_code` |

### Transfer

| Event | Action | Emitted by | Key fields |
|---|---|---|---|
| `file.upload` | `FILE_UPLOAD` | `SessionServer.do_upload` | `detail` (`local -> remote`), `local`, `remote` |
| `file.download` | `FILE_DOWNLOAD` | `SessionServer.do_download` | `detail` (`remote -> local`), `local`, `remote` |

### Errors

| Event | Emitted by | Key fields |
|---|---|---|
| `error` | `Session.connect`, `_degrade_to_hop`, `retry_target` | `message`, `host_id` |

Unexpected exceptions (anything that is not an `AccessControlError`) are **not**
audit records: the operator gets one clean line and the traceback is appended to
`<log dir>/errors.log` by `logging_setup.record_unexpected`.

---

## Worked example — one session's trail

```json
{"timestamp":"2026-08-12T09:15:20.100+00:00","seq":1,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"session.open","host_id":"win-app01","action":"SESSION_START","source":"local","target":"win-app01","result":"SUCCESS","detail":"local -> bastion1 (ssh) -> jump1 (winrm) -> win-app01 (nested winrm)","route":"local -> bastion1 (ssh) -> jump1 (winrm) -> win-app01 (nested winrm)","hops":[...],"allowed_operations":["install-package"],"client_host":"WS-AK01","client_os":"Windows-11","pid":18244}
{"timestamp":"2026-08-12T09:15:21.400+00:00","seq":2,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"hop.auth","host_id":"win-app01","hop_id":"bastion1","method":"publickey","username":"operator"}
{"timestamp":"2026-08-12T09:15:23.900+00:00","seq":3,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"hop.auth","host_id":"win-app01","hop_id":"bastion1","method":"password","username":"operator"}
{"timestamp":"2026-08-12T09:15:24.000+00:00","seq":4,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"ssh.connect","host_id":"win-app01","action":"SSH_CONNECT","source":"local","target":"bastion1","result":"SUCCESS","hop_id":"bastion1","endpoint":"bastion1.example.net:2222","channel":"ssh","username":"operator","auth_methods":["publickey","password"],"host_key":"known","preestablished":false,"duration_s":3.9}
{"timestamp":"2026-08-12T09:15:24.200+00:00","seq":5,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"tunnel.open","host_id":"win-app01","hop_id":"bastion1","target":"10.20.4.11:5985","local_port":53001,"purpose":"winrm:jump1"}
{"timestamp":"2026-08-12T09:15:24.210+00:00","seq":6,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"winrm.ntlm_provider","host_id":"win-app01","hop_id":"jump1","provider":"sspi","configured":"auto"}
{"timestamp":"2026-08-12T09:15:26.800+00:00","seq":7,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"winrm.connect","host_id":"win-app01","action":"WINRM_CONNECT","source":"bastion1","target":"jump1","result":"SUCCESS","endpoint":"10.20.4.11:5985","channel":"winrm","username":"corp\\jmpuser","domain":"corp","duration_s":2.5}
{"timestamp":"2026-08-12T09:15:41.000+00:00","seq":11,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"permission","host_id":"win-app01","action":"PERMISSION_REQUEST","source":"local","target":"win-app01","result":"BLOCKED","operation_id":"install-package","gated":true,"confirmed":false,"granted":false,"detail":"install-package awaiting operator approval"}
{"timestamp":"2026-08-12T09:16:05.300+00:00","seq":15,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"step.end","host_id":"win-app01","action":"SCRIPT_EXECUTE","source":"local","target":"win-app01","result":"FAILURE","operation_id":"install-package","step_id":"install","ok":false,"exit_code":1603,"duration_s":22.4,"expectation_reason":"expected exit code 0, got 1603","stdout_chars":184,"collected":2,"hint":"Generic MSI failure. ...","detail":"install-package/install"}
{"timestamp":"2026-08-12T09:16:09.100+00:00","seq":17,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"collect","host_id":"win-app01","action":"LOG_COLLECT","source":"local","target":"win-app01","result":"SUCCESS","step_id":"install","sources":["C:\\Windows\\Temp\\MSI*.LOG","eventlog:Application"],"exit_code":1603,"detail":"2 source(s) after install"}
{"timestamp":"2026-08-12T09:20:02.700+00:00","seq":24,"agentId":"AGT-20260812-3f9a1c","sessionId":"SES-3f9a1c","event":"session.close","host_id":"win-app01","action":"SESSION_END","source":"local","target":"win-app01","result":"SUCCESS","detail":"closed","status":"closed","elapsed_s":282.6,"records":23,"steps_run":3,"steps_ok":2,"steps_failed":1,"errors":0,"blocked":0,"log_file":"...\\20260812T091520Z-3f9a1c.jsonl"}
```

---

## Useful queries

```bash
# every command that was refused outright
jq -c 'select(.action=="COMMAND_BLOCKED")' *.jsonl

# every gated operation that was refused for want of approval
jq -c 'select(.action=="PERMISSION_REQUEST" and .result=="BLOCKED")' *.jsonl

# every route that bypassed the bastions
jq -c 'select(.event=="winrm.direct")' *.jsonl

# where the NTLM restriction was stepped around
jq -c 'select(.event=="winrm.ntlm_provider" and .provider=="python")' *.jsonl

# the slowest steps
jq -c 'select(.event=="step.end") | {op:.operation_id, step:.step_id, s:.duration_s}' *.jsonl \
  | sort -t: -k4 -rn | head

# sessions that never closed (credentials were not wiped by the normal path)
comm -23 <(jq -r 'select(.event=="session.open") |.sessionId' *.jsonl | sort -u) \
         <(jq -r 'select(.event=="session.close")|.sessionId' *.jsonl | sort -u)

# everything one agent run did, in order
jq -c 'select(.agentId=="AGT-20260812-3f9a1c")' *.jsonl
```

---

## Identity correlation

| Id | Scope | Where it appears |
|---|---|---|
| `agentId` | One agent instance / run | Every record. Override with `ac connect --agent-id` or `AC_AGENT_ID` |
| `sessionId` | One authenticated path | Every record; `ac status`, `ac audit`, `ac timeline` |
| `trace_id` | Sortable, filename-safe | The `.jsonl` / `.md` file name. Not inside the records |
| `seq` | Ordering within one session | Every record |
| `change_ref` | One change ticket | The brief and its reports — **not** in the JSONL |

`trace_id` is `<UTC timestamp>-<random suffix>`; the same suffix forms the
`sessionId` (`SES-3f9a1c`), which is not sortable — which is why files are
named by the trace id. The suffix is random rather than counted, so concurrent
sessions started by independent processes never share an id or a log file.

To bind a run to a person and a ticket, pass `--agent-id` (or set
`AC_AGENT_ID`) before connecting:

```powershell
$env:AC_AGENT_ID = "claude/j.doe/CHG0001234"
```

---

## Adding a new event

1. If it is a meaningful action against an operator's machines, add the name to
   `audit.ACTIONS` and use `audit.action(...)` with `source`, `target` and
   `result` — actions are what `ac timeline` and SIEM filters see.
2. Otherwise use `audit.emit("<dotted.name>", …)` for a state change worth
   recording that is not an action (`session.degraded`, `config.reload`).
3. Keep identity fields in canonical spelling and payload fields in snake_case.
4. Add the event to this document and, if it is security-relevant, to the
   detection tables in [../OPERATIONS.md](../OPERATIONS.md#42-signals-worth-alerting-on)
   and [../CLAUDE_PRODUCTION_GUARDRAILS.md](../CLAUDE_PRODUCTION_GUARDRAILS.md).
