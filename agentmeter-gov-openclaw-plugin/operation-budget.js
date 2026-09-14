import { createHash } from "node:crypto";


export function consumeOperationBudget(state, event, config = {}) {
  const name = String(event?.toolName ?? "").toLowerCase();
  const action = String(event?.params?.action ?? "").toLowerCase();
  if (name === "process" && /^(?:poll|log|list|status)$/.test(action)) return null;
  const limits = {
    total: bounded(config.maxToolCallsPerTurn, 16, 4, 100),
    search: bounded(config.maxSearchCallsPerTurn, 6, 1, 30),
    retry: bounded(config.maxIdenticalToolCallsPerTurn, 3, 1, 10),
  };
  const budget = state.operationBudget ?? { total: 0, search: 0, fingerprints: new Map() };
  state.operationBudget = budget;
  budget.total += 1;
  if (/(?:search|find|query|lookup|grep)/.test(name)) budget.search += 1;
  const fingerprint = createHash("sha256")
    .update(`${name}|${stableJson(event?.params ?? {})}`)
    .digest("hex")
    .slice(0, 16);
  const repeats = (budget.fingerprints.get(fingerprint) ?? 0) + 1;
  budget.fingerprints.set(fingerprint, repeats);
  if (repeats > limits.retry) return result("identical_retry_budget", budget, limits, name, repeats);
  if (budget.search > limits.search) return result("search_budget", budget, limits, name, repeats);
  if (budget.total > limits.total) return result("total_tool_budget", budget, limits, name, repeats);
  return null;
}


function result(reason, budget, limits, toolName, repeats) {
  return {
    reason,
    toolName,
    counts: { total: budget.total, search: budget.search, identical: repeats },
    limits,
    message: "AgentMeter-Gov 已停止本轮过量搜索或重复工具调用。请基于已有结果回答，或由用户缩小任务范围后重试。",
  };
}


function bounded(value, fallback, minimum, maximum) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}


function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
