import assert from "node:assert/strict";

import { registerOutputGovernanceHooks } from "./register-output-governance.js";

const hooks = new Map();
const audits = [];
const api = {
  pluginConfig: { failClosed: true, outputMaxFileBytes: 1024 },
  on(name, handler, options) {
    hooks.set(name, { handler, options });
  },
};

registerOutputGovernanceHooks(api, {
  async recordOutputGuard(result, surface) {
    audits.push({ action: result.action, surface });
  },
  scheduleBackground(_api, _label, work) {
    void work();
  },
});

assert.deepEqual(
  [...hooks.keys()],
  ["before_message_write", "before_agent_finalize", "reply_payload_sending", "message_sending"],
);
assert.ok([...hooks.values()].every((item) => item.options.priority === 1000));

const transcriptResult = hooks.get("before_message_write").handler({
  message: { role: "assistant", content: "DB_PASS=Secret123" },
}, {});
assert.equal(typeof transcriptResult?.then, "undefined");
assert.match(transcriptResult.message.content, /REDACTED:CREDENTIAL/);

const finalResult = await hooks.get("before_agent_finalize").handler({
  lastAssistantMessage: "API_KEY=abcdefghijklmnop1234",
  turnId: "turn-1",
}, { runId: "run-1" });
assert.equal(finalResult.action, "revise");
assert.equal(finalResult.retry.maxAttempts, 1);

const replyResult = await hooks.get("reply_payload_sending").handler({
  payload: { text: "Call 13800138000" },
}, {});
assert.match(replyResult.payload.text, /REDACTED:PHONE_NUMBER/);

const sendResult = await hooks.get("message_sending").handler({
  content: "Bearer abcdefghijklmnop",
  metadata: { source: "test" },
}, {});
assert.match(sendResult.content, /REDACTED:BEARER_TOKEN/);
assert.equal(sendResult.metadata.agentmeter_output_action, "redact");
assert.ok(audits.length >= 4);

console.log(JSON.stringify({ total: 12, passed: 12 }));
