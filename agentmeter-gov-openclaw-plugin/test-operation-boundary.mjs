import assert from "node:assert/strict";

import { boundaryAuditFields, classifyOperationBoundary } from "./operation-boundary.js";

const status = classifyOperationBoundary({
  event: { toolName: "exec", params: { command: "openclaw status --json" }, toolSource: "core" },
  ctx: { sessionKey: "agent:main:openclaw-weixin:direct:test@im.wechat" },
  proposed: { name: "read_document" },
});
assert.equal(status.local_allow, true);
assert.equal(status.operation_class, "control_plane_read");
assert.equal(status.channel_id, "openclaw-weixin");

const poll = classifyOperationBoundary({
  event: { toolName: "process", params: { action: "poll", sessionId: "safe-process" } },
  proposed: { name: "read_document" },
});
assert.equal(poll.local_allow, true);
assert.equal(poll.operation_class, "control_plane_continuation");

const pluginRead = classifyOperationBoundary({
  event: { toolName: "weather_lookup", params: { action: "get", city: "Xiongan" }, toolSource: "plugin", toolOwner: "weather" },
  proposed: { name: "web_fetch" },
});
assert.equal(pluginRead.local_allow, true);
assert.equal(pluginRead.tool_owner, "weather");

const untrustedClaim = classifyOperationBoundary({
  event: { toolName: "weather_lookup", params: { action: "get", toolSource: "plugin", toolOwner: "weather" } },
  proposed: { name: "web_fetch" },
});
assert.equal(untrustedClaim.local_allow, false);

const extensionSend = classifyOperationBoundary({
  event: { toolName: "send_message", params: { action: "send", recipient: "other" }, toolSource: "channel", toolOwner: "openclaw-weixin" },
  proposed: { name: "send_email" },
});
assert.equal(extensionSend.local_allow, false);

const pluginCredentialRead = classifyOperationBoundary({
  event: { toolName: "read_secret", params: { action: "read", credential: "api_token" }, toolSource: "plugin", toolOwner: "example" },
  proposed: { name: "read_secret" },
});
assert.equal(pluginCredentialRead.local_allow, false);

const arbitraryCommand = classifyOperationBoundary({
  event: { toolName: "exec", params: { command: "nvidia-smi" }, toolSource: "core" },
  proposed: { name: "run_shell" },
});
assert.equal(arbitraryCommand.local_allow, false);

const taintedStatus = classifyOperationBoundary({
  event: { toolName: "exec", params: { command: "openclaw status --json" }, toolSource: "core" },
  proposed: { name: "read_document" },
  taskRiskLocked: true,
});
assert.equal(taintedStatus.local_allow, false);

assert.deepEqual(boundaryAuditFields(status), {
  operation_class: "control_plane_read",
  evaluation_path: "local_allow_audit",
  tool_source: "core",
  tool_owner: "",
  channel_id: "openclaw-weixin",
});

console.log(JSON.stringify({ total: 9, passed: 9 }));
