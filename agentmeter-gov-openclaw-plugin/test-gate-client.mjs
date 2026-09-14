import assert from "node:assert/strict";
import { createServer } from "node:http";
import { requestGate } from "./gate-client.js";

const ok = () => ({ ok: true, json: async () => ({ gate_action: "allow", allowed: true }) });
const refused = () => new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } });
let requests = 0, recoveries = 0;
const recovered = await requestGate({}, {}, { ensureReady: async () => { recoveries++; return true; } }, async () => {
  if (++requests === 1) throw refused();
  return ok();
});
assert.equal(recovered.allowed, true);
assert.equal(requests, 2);
assert.equal(recoveries, 1);
assert.equal(recovered.gate_transport.attempts, 2);

for (const response of [
  () => { throw new TypeError("reset", { cause: { code: "ECONNRESET" } }); },
  () => ({ ok: false, status: 503 }),
  () => ({ ok: true, json: async () => { throw new SyntaxError("bad JSON"); } }),
  () => ({ ok: true, json: async () => ({ gate_action: "allow", allowed: false }) }),
]) {
  let replayed = false;
  const result = await requestGate({}, {}, { ensureReady: async () => { replayed = true; return true; } }, response);
  assert.equal(result.allowed, false);
  assert.equal(result.gate_action, "block");
  assert.equal(replayed, false, "Ambiguous POST failures must not replay state updates");
}

let lateRequests = 0;
const waiting = await requestGate({ gateTimeoutMs: 100 }, {}, { ensureReady: () => new Promise(resolve => setTimeout(() => resolve(true), 200)) }, async () => {
  lateRequests++;
  throw refused();
});
assert.equal(waiting.gate_transport.error_kind, "timeout");
assert(waiting.gate_transport.total_ms < 1000);
await new Promise(resolve => setTimeout(resolve, 220));
assert.equal(lateRequests, 1, "Recovery finishing after deadline must not send a late POST");

let received = 0;
const server = createServer((req, res) => {
  received++;
  res.writeHead(200, { "content-type": "application/json" });
  res.write('{"gate_action":'); // Headers arrive, response body stalls.
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
try {
  const result = await requestGate({ gateUrl: `http://127.0.0.1:${server.address().port}/gate`, gateTimeoutMs: 100 }, {});
  assert.equal(result.allowed, false);
  assert.equal(result.gate_transport.error_kind, "timeout");
  assert(result.gate_transport.total_ms < 1000);
  assert.equal(received, 1);
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
const open = await requestGate({ failClosed: false }, {}, null, () => { throw refused(); });
assert.equal(open.allowed, true, "Preserve explicit operator fail-open configuration");
console.log("Gate deadline, stalled body, bounded recovery, safe retry and fail-closed checks passed");
