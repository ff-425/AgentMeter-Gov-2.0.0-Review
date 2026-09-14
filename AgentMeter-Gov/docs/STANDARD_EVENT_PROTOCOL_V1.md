# AgentMeter Standard Event Protocol v1

All runtime adapters emit `agentmeter.event.v1` envelopes. Required envelope fields are `schema_version`, `adapter`, `event_type`, and `timestamp`; the normalizer adds `event_id`, `audit_id`, and `protocol_stage` when absent.

Supported stages are input, decision, tool result, output, memory, delegation, supply chain, and result. Adapter-specific metadata may remain in extra fields, but risk evaluation uses the canonical task, context, history, and operation fields below.

## Tool proposal

Send this runtime-neutral request to `POST /api/v1/evaluate`:

```json
{
  "schema_version": "agentmeter.event.v1",
  "adapter": "langgraph-or-other-runtime",
  "event_type": "tool_proposal",
  "timestamp": "2026-08-14T00:00:00Z",
  "audit_id": "AUD-123",
  "task": {
    "id": "TASK-123",
    "user_id": "user-1",
    "goal": "Read a public project document"
  },
  "context": {
    "session_key": "session-1",
    "input_sources": []
  },
  "history": [],
  "operation": {
    "name": "read_document",
    "parameters": {"path": "docs/readme.md"},
    "data_classification": "public",
    "source": "before_tool_call"
  }
}
```

Canonical operation fields are `name`, `parameters`, `data_classification`, `source`, `status`, and `evidence`. The adapter accepts legacy `proposed_tool_call` requests during migration, but OpenClaw itself now sends the canonical structure.

## Endpoints

- `POST /api/events`: normalize, sign, and persist any protocol event.
- `POST /api/v1/evaluate`: evaluate a canonical `tool_proposal` before execution.
- `POST /api/audit/verify`: verify the complete HMAC audit chain.
