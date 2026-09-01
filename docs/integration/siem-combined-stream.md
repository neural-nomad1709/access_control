# SIEM: the combined execution + governance stream

With the integration in place there are two evidence streams for the same
work, and both are already SIEM-shaped. This is how they land in one SIEM,
correlated, so an analyst sees an agent's whole story — what it was permitted
to do, and what it actually did — in one place.

## The two streams

| Stream | Producer | Shape | Correlation keys |
|---|---|---|---|
| **Execution** | access_control | One `*.jsonl` per session (`<log dir>/<trace_id>.jsonl`), fsynced, one JSON object per action | `agentId`, `sessionId`, `action`, `source`, `target`, `result`, `timestamp` |
| **Governance** | AgentLighthouse | The signed receipt ledger, exported as ECS/MITRE NDJSON (`al export --format siem`) | `user.id` = the SPIFFE actor, `action`, `verdict`, `block_reason`, `record_hash`, `sig` |

The execution stream is the operational record (every command, every hop, every
collected log). The governance stream is the **decision** record (every
authorize, approval, scan, and its signed receipt). When ac runs under the
`LighthouseGatekeeper`, every execution action is also mirrored into the
governance ledger as a receipt-v1.1 event (`session_open`, `remote_exec`,
`permission_request`, `session_close`), so the governance stream is a superset
of the decisions and a mirror of the actions.

## The join key

Both streams carry the agent identity, spelled two ways for the same subject:

- execution `agentId` — e.g. `AGT-20260901-3f9a1c`, or a pinned
  `--agent-id claude/j.doe/INC0001234`;
- governance `user.id` — the SPIFFE actor
  `spiffe://access-control/agent/<agent-id>`, lowercased and sanitized to
  `[a-z0-9._-]` (see `gatekeeper.spiffe_actor`).

The governance actor is a deterministic transform of the execution `agentId`:
lowercase, then replace every character outside `[a-z0-9._-]` with `-`. A SIEM
correlation rule derives one from the other, or — cleaner — **pin the agent id
at connect** (`ac connect --agent-id …`) so both streams carry a value you
chose, and join on it directly.

`sessionId` (execution) and the receipt `session` field (governance) both scope
to one authenticated path, giving a second, finer join for a single session's
timeline.

## Shipping both

1. **Execution** — forward `<log dir>/*.jsonl` to the SIEM (production-readiness
   recommended-work item 4). Records need no transform; the field names are
   canonical.
2. **Governance** — `al export --format siem --ledger <data-dir>/ledger.jsonl`
   emits ECS/MITRE NDJSON; each event carries `record_hash` + `sig`, so an
   analyst can pull the receipt and verify it independently with `al-verify`.
   Run it on a schedule, or stream the ledger's append path.

## What the join buys

- **A denied action explains itself.** The execution stream shows a command that
  did not run; the governance stream shows *why* — a `TOOL_DENIED`,
  `BUDGET_EXCEEDED`, or `HITL_DENIED` receipt against the same actor and session.
- **Tamper evidence on the decisions.** The execution JSONL is written by the
  audited process (R-09); the governance receipts are signed and hash-chained.
  A discrepancy between the two streams for the same `(actor, session, action)`
  is itself a signal.
- **One identity, fleet-wide.** Because the governance actor is per-agent, the
  SIEM can budget, alert, and report per agent identity across every host the
  agent touched.

## Not built here

This is a correlation pattern, not a new exporter — both streams already exist
and are SIEM-ready. A single process that merges them into one ordered feed is
possible but unbuilt: the SIEM is the natural place to join two sources on a
shared key, and building a combiner would put a second writer between the
signed ledger and the analyst for no evidence gain.
