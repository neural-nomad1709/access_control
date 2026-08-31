# Session protocol

The wire protocol between `ac connect` (which holds the authenticated path) and
every other command (which attaches to it).

Implemented in `daemon.py`. `PROTOCOL_VERSION = 1`.

---

## Why it exists

Building the hop chain costs the operator a password at every hop. Doing that per
command would make a twenty-step patch run unusable, and Windows OpenSSH has no
`ControlMaster` to lean on — so the session is held in a process of its own and
driven over a loopback socket.

The shape falls straight out of the credential rule:

- **`ac connect` runs in the operator's own terminal, in the foreground.** That is
  the only place a `getpass` prompt can appear, so that is where passwords are
  typed. The window stays open for the life of the task.
- **`ac run` / `ac exec` / an agent are thin clients.** They attach by host id and
  never see a credential.

---

## Discovery: the descriptor file

```
<app data>/sessions/<sanitised host id>.json      mode 0600
```

The host id is sanitised by replacing every character that is not alphanumeric,
`-` or `_` with `_`.

```json
{
  "version": 1,
  "host_id": "win-app01",
  "session_id": "SES-3f9a1c",
  "port": 53187,
  "token": "<43-char urlsafe base64, 256 bits>",
  "pid": 18244,
  "started": 1755000920.13,
  "agent_id": "AGT-20260812-3f9a1c"
}
```

Written with `os.open(..., O_WRONLY|O_CREAT|O_TRUNC, 0o600)` **before** anything
is written to it, so the token is never briefly world-readable. Removed on
shutdown.

`attach(host_id)` reads it, pings, and returns a client — or removes a stale
descriptor and returns `None` so a dead session cannot produce confusing errors
later. A descriptor whose `version` does not match is ignored.

---

## Transport

| Property | Value |
|---|---|
| Address | `127.0.0.1`, ephemeral port (`bind(("127.0.0.1", 0))`) |
| Backlog | 8; `accept` polls with a 1 s timeout so the loop can be stopped |
| Framing | One line of JSON in, one line of JSON out (`\n` terminated) |
| Size limit | 8 MiB per request and per response (`RECV_LIMIT`) |
| Client connect timeout | 15 s |
| Client read timeout | 3600 s (a step can legitimately take an hour) |
| Server per-request timeout | 3600 s |
| Concurrency | One thread per request |

## Authentication

Every request carries the token from the descriptor, compared with
`secrets.compare_digest`. A mismatch returns
`{"ok": false, "error": "invalid session token"}`.

**This is a convenience boundary, not a privilege boundary.** Any process running
as the same user can read the descriptor and drive the session — the same trust
level as an `ssh-agent` socket. It protects against other users on the machine
and against the network. See
[../SECURITY.md](../SECURITY.md#6-session-management).

---

## Message format

**Request**

```json
{"token": "…", "method": "run_operation", "params": {"operation_id": "windows-health"}}
```

**Response — success**

```json
{"ok": true, "result": { … }}
```

**Response — failure**

```json
{"ok": false, "error": "operation 'x' needs the operator's approval…", "error_type": "PermissionRequired"}
```

`error_type` is present for `AccessControlError` subclasses; an unexpected
exception returns `{"ok": false, "error": "<Type>: <message>"}` with no type
field. **One bad request never kills the session** — errors are returned, not
raised out of the handler.

Serialisation uses `json.dumps(..., default=str)`, so `Path` and datetime values
survive as strings.

---

## Methods

Dispatch is by name: a method `x-y` calls `do_x_y(**params)`. Adding a method
means adding `do_<name>` to `SessionServer` — the dispatcher finds it.

| Method | Params | Returns | Used by |
|---|---|---|---|
| `ping` | — | `{session_id, host_id}` | `attach()` liveness |
| `status` | — | The full session status (see below) | `ac status <host>` |
| `preflight` | `spec` | `PreflightReport.to_dict()`: `{host_id, ok, checks[], blockers[], warnings[], duration_s}` | `ac verify`, `ac brief run`, campaigns |
| `operations` | — | The operations this session may run | agents |
| `reload` | — | `{host_id, operations[], added[], removed[], warnings[], route}` | `ac reload` |
| `preview` | `operation_id`, `params` | The rendered preview | agents |
| `run_operation` | `operation_id`, `params`, `confirmed`, `dry_run`, `only_steps`, `start_at` | `OperationOutcome.to_dict()` | `ac run`, `ac brief run`, campaigns |
| `run_command` | `command`, `shell`, `confirmed`, `timeout_s` | `ExecResult.to_dict()` | `ac exec` |
| `fetch_log` | `path`, `tail` | `ExecResult.to_dict()` | `ac logs` |
| `upload` | `local_path`, `remote_path` | `{uploaded}` | `ac upload` |
| `download` | `remote_path`, `local_path` | `{downloaded}` | `ac download` |
| `open_tunnel` | `dest_host`, `dest_port`, `purpose`, `local_port` | `{tunnel_id, local_host, local_port, dest}` | `ac rdp`, `ac shell`, `ac tunnel` |
| `close_tunnel` | `tunnel_id` | `{closed}` | same |
| `credentials_for` | `node_id` | `{node_id, username}` | `ac rdp` (pre-fills the username) |
| `close` | `status` | The final status, with `closing: true` | `ac disconnect` |

**`credentials_for` returns a username only. Passwords never cross this socket.**
There is no method that returns a secret.

Every method that does work calls `session.touch()` first, so activity resets the
idle timer.

### `status` result

```json
{
  "session_id": "SES-3f9a1c", "agent_id": "AGT-20260812-3f9a1c", "host_id": "win-app01",
  "elapsed_s": 282.6, "records": 23,
  "steps_run": 3, "steps_ok": 2, "steps_failed": 1, "errors": 0, "blocked": 0,
  "log_file": "…/20260812T091520Z-845921.jsonl",
  "route": "local -> bastion1 (ssh) -> jump1 (winrm) -> win-app01 (nested winrm)",
  "hops": [ … ], "channel": "nested-winrm",
  "degraded": false, "degraded_reason": null,
  "current_node": "win-app01", "current_address": "corp\\svc_deploy@win-app01.corp.net",
  "connected": true, "closed": false, "connected_at": 1755000926.8,
  "idle_s": 4.2, "idle_timeout_s": 1800, "expires_in_s": 1796,
  "allowed_operations": ["install-package"],
  "authenticated_nodes": ["bastion1", "jump1", "win-app01"],
  "tunnels": [{"local": "127.0.0.1:53001", "to": "10.20.4.11:5985", "active": true}]
}
```

---

## Lifecycle

```
serve_forever()
  ├─ bind, listen, write descriptor
  ├─ on_ready(descriptor)          → the CLI prints the "session open" panel
  ├─ start the idle watchdog       (polls every 15 s)
  ├─ accept loop, thread per request
  └─ shutdown(status)
       ├─ stop every tunnel this server opened
       ├─ close the listener, remove the descriptor
       └─ session.close(status)    → tunnels, channels, hops reversed;
                                     credentials and the redaction registry wiped
```

`ac connect` runs `serve_forever` on a background thread and the operator prompt
in the foreground, so an agent can attach to the very session the operator is
typing into — one authenticated path, two users of it. With `--no-shell` the
server runs in the foreground instead.

### Deferred close

`do_close` returns the report and sets `_close_after_reply`; the actual teardown
happens in the request handler's `finally`, **after** the reply is on the wire and
the socket is closed. Shutting down inside the handler races the reply, and
whoever typed `ac disconnect` would get a connection error instead of the status
they are owed. There is a regression test for this
(`test_daemon.py::test_close_returns_the_report_before_tearing_down`).

### Idle watchdog

A daemon thread waits on the stop event with a 15 s timeout. On expiry it emits
`session.idle_timeout`, sets the stop flag, and opens a throwaway connection to
its own port to nudge `accept()` out of its timeout so `serve_forever` returns
promptly.

---

## Client behaviour

```python
from access_control.daemon import attach

client = attach("win-app01")          # None if no live session
if client is None:
    ...                                # tell the human to run `ac connect`
result = client.call("run_operation", operation_id="windows-health")
```

`SessionClient.call` raises `SessionError` if the socket cannot be reached or the
session closed without replying, and `AccessControlError` carrying the server's
message when `ok` is false. The CLI turns both into one clean line.

---

## Sessions without a daemon

`EphemeralSession` builds, uses and tears down a session inside a single command.
It is the fallback for `ac rdp` / `ac shell` / `ac tunnel` when nothing is live,
and for `ac run --dry-run` / `ac preview` (which connect to nothing at all).

Every hop prompts again — through the Windows credential dialog if there is no
terminal — so it is fine for a one-shot and painful for a twenty-step operation.
It **disables hop fallback** deliberately: a one-shot command that silently ran
somewhere other than where it was aimed would be a lie.
