// A finished agent turn and a successful business operation are different facts.
export function agentExecutionOutcome(event = {}) {
  const messages = Array.isArray(event.messages) ? event.messages : [];
  const lastAssistant = messages.map(item => item?.message ?? item)
    .filter(item => item?.role === "assistant").at(-1);
  const stopReason = String(lastAssistant?.stopReason ?? lastAssistant?.stop_reason ?? "").toLowerCase();
  const failure = event.success === false || Boolean(event.error) || event.aborted === true ||
    ["error", "aborted", "terminated", "cancelled", "canceled"].includes(stopReason);
  const rawError = event.error || (failure ? lastAssistant?.errorMessage || lastAssistant?.error : "");
  const error = typeof rawError === "string" ? rawError : typeof rawError?.message === "string" ? rawError.message : "";
  return {
    execution_result: failure ? "failed" : event.success === true || lastAssistant ? "completed" : "incomplete",
    execution_error: failure ? (error || stopReason || "OpenClaw reported an unsuccessful run").slice(0,1000) : "",
    stop_reason: stopReason,
  };
}

export function toolExecutionOutcome(event = {}, blocked = false) {
  const result = event.result ?? {};
  const details = result.details ?? event.details ?? {};
  const status = String(details.status ?? result.status ?? "").toLowerCase();
  if (event.error || result.isError === true || blocked || ["failed", "error", "blocked", "denied"].includes(status) ||
      (typeof details.exitCode === "number" && details.exitCode !== 0)) return "failed";
  if (["running", "pending", "queued", "in_progress"].includes(status)) return "pending";
  return "success";
}
