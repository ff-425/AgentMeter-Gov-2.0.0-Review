const DEFAULT_PENDING_TTL_MS = 30 * 60 * 1000;

function hasReviewTarget(item) {
  return Boolean(
    item?.targetKey
    || item?.proposedToolCall?.params?.path
    || item?.proposedToolCall?.params?.file
    || item?.proposedToolCall?.params?.to,
  );
}

function recentPending(store, now, ttlMs) {
  return (store?.pending ?? []).filter((item) => {
    if (!item || item.consumed || item.rejected) return false;
    const createdAt = Date.parse(item.createdAt ?? "");
    return Number.isFinite(createdAt) && now >= createdAt && now - createdAt <= ttlMs;
  });
}

/**
 * Select a review without letting a vague "approve" message release another
 * conversation's task.  A cross-session approval is permitted only when the
 * user supplies the exact review ID, which acts as the correlation token.
 */
export function selectPendingReviewForContext(store, options = {}) {
  const reviewId = String(options.reviewId ?? "").trim().toLowerCase();
  const sessionKey = String(options.sessionKey ?? "");
  const now = Number.isFinite(options.now) ? Number(options.now) : Date.now();
  const ttlMs = Number.isFinite(options.ttlMs)
    ? Math.max(1000, Number(options.ttlMs))
    : DEFAULT_PENDING_TTL_MS;
  const pending = recentPending(store, now, ttlMs);

  if (reviewId) {
    return pending.find((item) => String(item.reviewId ?? "").toLowerCase() === reviewId) ?? null;
  }
  if (!sessionKey) return null;
  const sameSession = pending
    .filter((item) => String(item.sessionKey ?? "") === sessionKey)
    .sort((a, b) => Date.parse(b.createdAt ?? "") - Date.parse(a.createdAt ?? ""));
  return sameSession.find((item) => hasReviewTarget(item)) ?? sameSession[0] ?? null;
}

/** Bind the release token to the session where the reviewed action originated.
 * A Weixin/mobile conversation acts only as the approver; the paused action is
 * resumed in its original conversation, whose session already exists and owns
 * the reviewed context. Both session identities remain available for audit.
 */
export function bindApprovalSession(pending, approvalSessionKey) {
  const originSessionKey = String(pending?.sessionKey ?? "");
  const currentSessionKey = String(approvalSessionKey ?? "");
  const releaseSessionKey = originSessionKey || currentSessionKey;
  return {
    originSessionKey,
    approvalSessionKey: currentSessionKey,
    releaseSessionKey,
    crossSession: Boolean(originSessionKey && currentSessionKey && originSessionKey !== currentSessionKey),
  };
}

export function approvalContinuationContext(approval) {
  const reviewId = String(approval?.reviewId ?? "").trim();
  const originalUserGoal = String(approval?.originalUserGoal ?? "").trim();
  if (!reviewId || !originalUserGoal) return "";
  return [
    "[AgentMeter-Gov verified human approval]",
    `Review ${reviewId} was explicitly approved. Resume the reviewed action now; do not search files, memory or logs for the approval ID.`,
    "The approval covers only the exact reviewed action. Every different or higher-risk action remains subject to the normal safety gate.",
    "This controlled continuation replaces ordinary heartbeat housekeeping for this turn. Execute the reviewed action once and finish; do not read HEARTBEAT.md or perform unrelated checks.",
    "Original reviewed user request:",
    originalUserGoal.slice(0, 2000),
  ].join("\n");
}

export function selectApprovedContinuationForSession(store, options = {}) {
  const sessionKey = String(options.sessionKey ?? "").trim();
  const now = Number.isFinite(options.now) ? Number(options.now) : Date.now();
  if (!sessionKey) return null;
  return (store?.approvals ?? [])
    .filter((item) => {
      if (!item || item.consumed || item.rejected) return false;
      if (String(item.sessionKey ?? "") !== sessionKey) return false;
      if (!String(item.reviewId ?? "").trim() || !String(item.originalUserGoal ?? "").trim()) return false;
      const expiresAt = Date.parse(item.expiresAt ?? "");
      return !Number.isFinite(expiresAt) || now <= expiresAt;
    })
    .sort((a, b) => Date.parse(b.approvedAt ?? "") - Date.parse(a.approvedAt ?? ""))[0] ?? null;
}

/**
 * Resume an approved action without asking the model to interpret the approval
 * sentence. Installed plugins cannot use OpenClaw's bundled-only Cron turn
 * scheduler. The preferred path stores the approval durably, contributes the
 * original goal only to the originating session's next heartbeat, and wakes
 * that session immediately. A next-turn injection remains as a compatibility
 * fallback. The normal before_tool_call gate still validates the resulting
 * call against the one-use approval signature.
 */
export async function requestApprovedContinuation(api, approval, options = {}) {
  const sessionKey = String(options.sessionKey ?? approval?.approvalSessionKey ?? "").trim();
  const text = approvalContinuationContext(approval);
  if (!sessionKey || !text) {
    return { requested: false, queued: false, reason: "missing_session_or_goal" };
  }

  const runtimeSystem = api?.runtime?.system;
  const requestWake = () => {
    const wakeOptions = {
      source: "hook",
      intent: "immediate",
      reason: `AgentMeter-Gov approval ${String(approval?.reviewId ?? "")}`,
      sessionKey,
      ...(options.agentId ? { agentId: String(options.agentId) } : {}),
    };
    if (typeof runtimeSystem?.requestHeartbeat === "function") {
      runtimeSystem.requestHeartbeat(wakeOptions);
      return "heartbeat_requested";
    }
    if (typeof runtimeSystem?.requestHeartbeatNow === "function") {
      runtimeSystem.requestHeartbeatNow(wakeOptions);
      return "legacy_heartbeat_requested";
    }
    return "wake_api_unavailable";
  };

  // The approval store is the durable queue. The heartbeat contribution hook
  // reads it only for the matching originating session, avoiding OpenClaw's
  // generic next-turn queue (which is not available in every plugin host).
  if (options.approvalStoreFallback === true) {
    const wakeReason = requestWake();
    return wakeReason === "wake_api_unavailable"
      ? { requested: false, queued: true, reason: wakeReason }
      : { requested: true, queued: true, reason: `approval_store_${wakeReason}` };
  }

  const enqueue = api?.session?.workflow?.enqueueNextTurnInjection
    ?? api?.enqueueNextTurnInjection;
  if (typeof enqueue !== "function") {
    return { requested: false, queued: false, reason: "next_turn_injection_api_unavailable" };
  }

  const enqueueResult = await enqueue({
    sessionKey,
    text,
    placement: "prepend_context",
    ttlMs: 2 * 60 * 1000,
    idempotencyKey: `agentmeter-approval:${String(approval?.reviewId ?? "unknown")}`,
    metadata: {
      workflow: "agentmeter_human_review_continuation",
      reviewId: String(approval?.reviewId ?? ""),
    },
  });
  const queued = Boolean(enqueueResult?.enqueued);
  if (!queued) {
    return { requested: false, queued: false, reason: "next_turn_injection_not_queued" };
  }

  const wakeReason = requestWake();
  if (wakeReason === "heartbeat_requested") {
    return { requested: true, queued: true, reason: "heartbeat_requested" };
  }
  if (wakeReason === "legacy_heartbeat_requested") {
    return { requested: true, queued: true, reason: "legacy_heartbeat_requested" };
  }
  return { requested: false, queued: true, reason: "wake_api_unavailable" };
}

export const APPROVAL_PENDING_TTL_MS = DEFAULT_PENDING_TTL_MS;
