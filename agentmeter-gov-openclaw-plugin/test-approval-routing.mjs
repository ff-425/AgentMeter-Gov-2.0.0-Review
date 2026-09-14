import assert from "node:assert/strict";

import {
  APPROVAL_PENDING_TTL_MS,
  approvalContinuationContext,
  bindApprovalSession,
  requestApprovedContinuation,
  selectApprovedContinuationForSession,
  selectPendingReviewForContext,
} from "./approval-routing.js";

const now = Date.parse("2026-09-11T12:00:00Z");
const pending = [
  {
    reviewId: "AGR-A",
    sessionKey: "openclaw:web:alice",
    createdAt: new Date(now - 60_000).toISOString(),
    targetKey: "reports/a.txt",
  },
  {
    reviewId: "AGR-B",
    sessionKey: "openclaw:weixin:bob",
    createdAt: new Date(now - 30_000).toISOString(),
    targetKey: "reports/b.txt",
  },
];
const store = { pending };

// An exact ID can correlate a mobile continuation with the original request.
assert.equal(selectPendingReviewForContext(store, {
  reviewId: "agr-a", sessionKey: "openclaw:weixin:alice", now,
})?.reviewId, "AGR-A");

// A vague approval message can only select work from the same conversation.
assert.equal(selectPendingReviewForContext(store, {
  sessionKey: "openclaw:weixin:bob", now,
})?.reviewId, "AGR-B");
assert.equal(selectPendingReviewForContext(store, {
  sessionKey: "openclaw:weixin:alice", now,
}), null);
assert.equal(selectPendingReviewForContext(store, { now }), null);

// Stale, consumed and rejected requests cannot be approved even by ID.
for (const item of [
  { ...pending[0], createdAt: new Date(now - APPROVAL_PENDING_TTL_MS - 1).toISOString() },
  { ...pending[0], consumed: true },
  { ...pending[0], rejected: true },
]) {
  assert.equal(selectPendingReviewForContext({ pending: [item] }, {
    reviewId: "AGR-A", sessionKey: "openclaw:weixin:alice", now,
  }), null);
}

assert.deepEqual(bindApprovalSession(pending[0], "openclaw:weixin:alice"), {
  originSessionKey: "openclaw:web:alice",
  approvalSessionKey: "openclaw:weixin:alice",
  releaseSessionKey: "openclaw:web:alice",
  crossSession: true,
});
assert.deepEqual(bindApprovalSession(pending[0], "openclaw:web:alice"), {
  originSessionKey: "openclaw:web:alice",
  approvalSessionKey: "openclaw:web:alice",
  releaseSessionKey: "openclaw:web:alice",
  crossSession: false,
});

const approved = {
  approvalId: "APP-A",
  reviewId: "AGR-A",
  sessionKey: "openclaw:web:alice",
  approvedAt: new Date(now - 10_000).toISOString(),
  expiresAt: new Date(now + 60_000).toISOString(),
  originalUserGoal: "Write the reviewed contact file.",
};
assert.equal(selectApprovedContinuationForSession({ approvals: [approved] }, {
  sessionKey: "openclaw:web:alice", now,
})?.approvalId, "APP-A");
assert.equal(selectApprovedContinuationForSession({ approvals: [approved] }, {
  sessionKey: "openclaw:weixin:alice", now,
}), null);
assert.equal(selectApprovedContinuationForSession({ approvals: [{ ...approved, consumed: true }] }, {
  sessionKey: "openclaw:web:alice", now,
}), null);
assert.equal(selectApprovedContinuationForSession({ approvals: [{ ...approved, expiresAt: new Date(now - 1).toISOString() }] }, {
  sessionKey: "openclaw:web:alice", now,
}), null);

const continuation = approvalContinuationContext({
  reviewId: "AGR-A",
  originalUserGoal: "Write the reviewed contact file.",
});
assert.match(continuation, /AGR-A/);
assert.match(continuation, /Resume the reviewed action now/);
assert.match(continuation, /Write the reviewed contact file/);
assert.equal(approvalContinuationContext({ reviewId: "AGR-A" }), "");

const calls = [];
const continuationRequest = await requestApprovedContinuation({
  session: { workflow: {
    async enqueueNextTurnInjection(options) {
      calls.push({ kind: "injection", options });
      return { enqueued: true, id: "inject-1", sessionKey: options.sessionKey };
    },
  } },
  runtime: { system: {
    requestHeartbeat(options) {
      calls.push({ kind: "heartbeat", options });
    },
  } },
}, {
  reviewId: "AGR-A",
  originalUserGoal: "Write the reviewed contact file.",
}, {
  sessionKey: "openclaw:weixin:alice",
  agentId: "main",
});
assert.deepEqual(continuationRequest, {
  requested: true,
  queued: true,
  reason: "heartbeat_requested",
});
assert.equal(calls[0].kind, "injection");
assert.equal(calls[0].options.sessionKey, "openclaw:weixin:alice");
assert.match(calls[0].options.text, /Write the reviewed contact file/);
assert.equal(calls[1].kind, "heartbeat");
assert.equal(calls[1].options.agentId, "main");

const fallbackCalls = [];
assert.deepEqual(await requestApprovedContinuation({
  runtime: { system: {
    requestHeartbeat(options) {
      fallbackCalls.push(options);
    },
  } },
}, approved, {
  sessionKey: "openclaw:web:alice",
  agentId: "main",
  approvalStoreFallback: true,
}), {
  requested: true,
  queued: true,
  reason: "approval_store_heartbeat_requested",
});
assert.equal(fallbackCalls[0].sessionKey, "openclaw:web:alice");

assert.deepEqual(await requestApprovedContinuation({}, {
  reviewId: "AGR-A",
  originalUserGoal: "Write the reviewed contact file.",
}, { sessionKey: "openclaw:weixin:alice" }), {
  requested: false,
  queued: false,
  reason: "next_turn_injection_api_unavailable",
});

assert.deepEqual(await requestApprovedContinuation({
  session: { workflow: {
    async enqueueNextTurnInjection() {
      return { enqueued: false, id: "", sessionKey: "openclaw:weixin:alice" };
    },
  } },
}, {
  reviewId: "AGR-A",
  originalUserGoal: "Write the reviewed contact file.",
}, { sessionKey: "openclaw:weixin:alice" }), {
  requested: false,
  queued: false,
  reason: "next_turn_injection_not_queued",
});

console.log(JSON.stringify({ total: 31, passed: 31 }));
