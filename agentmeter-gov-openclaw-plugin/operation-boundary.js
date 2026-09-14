import {
  isReadOnlyOpenClawCommand,
  isReadOnlyProcessAction,
} from "./interaction-ux.js";

const SENSITIVE_OR_MUTATING_PARAM = /(?:password|secret|token|api[_-]?key|credential|private[_-]?key|authorization|cookie|upload|attachment|recipient|payee|amount|delete|remove|write|update|create|send|post|publish|grant|approve)/i;

/**
 * Split OpenClaw tool traffic into a narrow local fast path and the normal
 * AgentMeter-Gov risk path. toolSource/toolOwner are host-authoritative fields
 * in current OpenClaw builds; values inside tool params are never trusted as
 * provenance.
 */
export function classifyOperationBoundary({ event = {}, ctx = {}, proposed = {}, taskRiskLocked = false } = {}) {
  const rawToolName = String(event?.toolName ?? ctx?.toolName ?? "").trim();
  const toolSource = normalizeToolSource(event?.toolSource ?? ctx?.toolSource);
  const toolOwner = trustedIdentity(event?.toolOwner ?? ctx?.toolOwner);
  const channelId = trustedIdentity(ctx?.channelId ?? event?.channelId) || channelFromSession(ctx?.sessionKey);
  const base = {
    version: "operation-boundary-v1",
    operation_class: "user_business_action",
    evaluation_path: "full_risk_gate",
    local_allow: false,
    fallback_eligible: false,
    tool_source: toolSource,
    tool_owner: toolOwner,
    channel_id: channelId,
    reason: "Tool action requires normal AgentMeter-Gov evaluation.",
  };

  if (taskRiskLocked) {
    return { ...base, reason: "Task context is already blocked or tainted; no compatibility fast path is allowed." };
  }

  if (rawToolName === "process" && isReadOnlyProcessAction(event?.params)) {
    return localDecision(base, "control_plane_continuation", "Read-only process polling/log retrieval continues an already governed action.");
  }

  if (rawToolName === "exec" && isReadOnlyOpenClawCommand(event?.params)) {
    return localDecision(base, "control_plane_read", "Exact OpenClaw status/health/version query has no business side effect.");
  }

  if (["plugin", "channel", "mcp"].includes(toolSource)
      && toolOwner
      && isSafeExtensionRead(event, proposed)) {
    return localDecision(base, "extension_read_only", `Host-owned ${toolSource} tool performs a metadata/read-only operation.`);
  }

  return base;
}

export function boundaryAuditFields(boundary = {}) {
  return {
    operation_class: boundary.operation_class ?? "user_business_action",
    evaluation_path: boundary.evaluation_path ?? "full_risk_gate",
    tool_source: boundary.tool_source ?? "core",
    tool_owner: boundary.tool_owner ?? "",
    channel_id: boundary.channel_id ?? "",
  };
}

function localDecision(base, operationClass, reason) {
  return {
    ...base,
    operation_class: operationClass,
    evaluation_path: "local_allow_audit",
    local_allow: true,
    fallback_eligible: true,
    reason,
  };
}

function isSafeExtensionRead(event, proposed) {
  const params = event?.params && typeof event.params === "object" ? event.params : {};
  const action = String(params.action ?? params.operation ?? "").toLowerCase().trim();
  const rawName = String(event?.toolName ?? "").trim();
  const proposedName = String(proposed?.name ?? "").trim();
  if (!["read_document", "web_search", "web_fetch"].includes(proposedName)) return false;
  if (action && !["get", "health", "list", "log", "lookup", "poll", "read", "search", "status"].includes(action)) return false;
  const serialized = JSON.stringify(params);
  if (SENSITIVE_OR_MUTATING_PARAM.test(serialized)) return false;
  return !/(?:send|post|publish|upload|delete|remove|write|edit|grant|approve|payment|transfer)/i.test(rawName);
}

function normalizeToolSource(value) {
  const normalized = String(value ?? "core").toLowerCase().trim();
  return ["core", "plugin", "channel", "mcp"].includes(normalized) ? normalized : "core";
}

function trustedIdentity(value) {
  const text = String(value ?? "").trim();
  return /^[a-z0-9][a-z0-9._:@/-]{0,160}$/i.test(text) ? text : "";
}

function channelFromSession(sessionKey) {
  const match = String(sessionKey ?? "").match(/^agent:[^:]+:([^:]+):/i);
  return trustedIdentity(match?.[1] ?? "");
}
