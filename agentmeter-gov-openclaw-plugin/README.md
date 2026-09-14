# AgentMeter-Gov Guard for OpenClaw

This plugin connects OpenClaw to the AgentMeter-Gov risk measurement loop. It blocks malicious persistent instructions at the input gate, evaluates tool calls through `AgentMeter-Gov /api/gate`, and writes structured audit events.

## Core Flow

```text
OpenClaw before_agent_run
  -> input-level persistent instruction assessment
  -> risk score + block before model execution when malicious
OpenClaw before_tool_call
  -> AgentMeter-Gov /api/gate
  -> risk score + matched rules
  -> allow / human_review / block (bypass is test-only)
  -> JSONL audit record
OpenClaw tool_result_persist / before_message_write / before_agent_finalize
  -> credential, token, private-key and personal-data inspection
  -> redact or request a safe final-answer revision
OpenClaw reply_payload_sending / message_sending
  -> inspect outgoing text, rich payloads and local file attachments
  -> remove unsafe attachments or redact outgoing content
```

`agent_end` is postflight observation only. A finding at that stage is recorded as
`output_postflight_event` and is treated as a missed leak, never as a successful block.

Tool-call governance and output governance are separate axes. Every tool decision is
audited, so there is no separate `allow_with_audit` action. Output content uses
`allow / redact / block`; `redact` replaces the detected secret value with a typed
placeholder such as `[REDACTED:API_TOKEN]` while preserving safe surrounding text.

## Mandatory Enforcement

AgentMeter-Gov Guard is a formal always-on protection layer for OpenClaw. After the plugin is installed and enabled, every OpenClaw tool call is evaluated before execution.

### Low-interference operation boundary

The guard keeps three enforcement outcomes (`allow`, `human_review`, `block`) while using two evaluation paths:

- Exact read-only OpenClaw status/health/version commands and read-only process polling use a local allow-and-audit fast path.
- Host-identified plugin/channel/MCP reads can use the same fast path only after their canonical action is already classified as read-only and their parameters contain no sensitive or mutating target.
- Writes, external sends, cross-recipient actions, attachments, credentials, payments, authorization changes, approvals, deletions and unknown operations always use the full risk gate.

Fast-path operations are still written to the audit trail, their returned content is still inspected for hidden instructions, and all outbound text remains under output governance. Provenance comes from OpenClaw's host-authoritative `toolSource` and `toolOwner` fields; similarly named values inside tool parameters never grant trust.

There is no natural-language runtime switch. Requests such as `disable guard`, `bypass AgentMeter-Gov`, or `关闭防护` are treated as protection-bypass attempts and are blocked/audited.

## Configuration

The plugin calls the local AgentMeter-Gov service by default:

```text
http://127.0.0.1:8765/api/v1/evaluate
```

Runtime files are resolved from `runtimeDir`, or from the `AGENTMETER_GOV_HOME` environment variable if `runtimeDir` is not set.

When the OpenClaw Gateway starts, the plugin registers the `agentmeter-gov-backend`
service. It reuses an existing healthy local backend or starts `server.py`
automatically. Discovery and metadata-only plugin loads never start a process.
Set `autoStartBackend: false` only when an operator manages the backend separately.

Default runtime files:

```text
data/openclaw_guard_flow_events.jsonl
data/openclaw_guard_approvals.json
data/openclaw_guard_batch_state.json
data/review_memory.json
data/memory_governance_state.json
```

The output gate scans local text attachments up to `outputMaxFileBytes` (1 MiB by
default). Unsupported binary attachments, oversized files and unreadable files are
removed when `failClosed` is enabled. Remote links are allowed only when the URL does
not contain a detected credential or signed secret parameter.

Recommended persistent configuration:

```powershell
openclaw config set plugins.entries.agentmeter-gov-guard.config.runtimeDir "D:\GitHub\AgentMeter-Gov\AgentMeter-Gov"
openclaw config set plugins.entries.agentmeter-gov-guard.config.autoStartBackend true
```

## Install

Install from the local plugin folder:

```powershell
openclaw plugins install "D:\GitHub\AgentMeter-Gov\agentmeter-gov-openclaw-plugin" --force
openclaw plugins enable agentmeter-gov-guard
openclaw gateway restart
```

Restart the OpenClaw Gateway after installing or editing the plugin. The backend
and monitoring page then start automatically; no separate `python server.py`
terminal is required.

## Minimal Check

```powershell
node --check agentmeter-gov-openclaw-plugin\index.js
npm --prefix agentmeter-gov-openclaw-plugin test
openclaw config validate
```
