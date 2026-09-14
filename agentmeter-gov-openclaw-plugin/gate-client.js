// One deadline covers the request body, response body and optional cold-start recovery.
export async function requestGate(config, payload, backendService = null, fetchImpl = fetch) {
  const configured = Number(config.gateTimeoutMs ?? 10000);
  const timeoutMs = Number.isFinite(configured) ? Math.max(100, Math.min(60000, configured)) : 10000;
  const started = performance.now();
  const controller = new AbortController();
  const timings = { timeout_ms: timeoutMs, attempts: 0, request_ms: 0, recovery_ms: 0 };
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(`Gate deadline exceeded (${timeoutMs} ms)`);
      error.name = "TimeoutError";
      controller.abort(error);
      reject(error);
    }, timeoutMs);
  });
  const bounded = operation => Promise.race([operation, deadline]);
  const request = async () => {
    controller.signal.throwIfAborted();
    timings.attempts++;
    const at = performance.now();
    try {
      const token = String(config.apiToken ?? process.env.AGENTMETER_API_TOKEN ?? "").trim();
      const response = await bounded(fetchImpl(String(config.gateUrl ?? "http://127.0.0.1:8765/api/v1/evaluate"), {
        method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(payload), signal: controller.signal,
      }));
      if (!response.ok) {
        void response.body?.cancel().catch(() => {});
        throw new Error(`HTTP ${response.status}`);
      }
      const result = await bounded(response.json());
      if (!result || !["allow", "block", "human_review"].includes(result.gate_action) ||
          result.allowed !== (result.gate_action === "allow")) throw new Error("Invalid gate response");
      return result;
    } finally {
      timings.request_ms += performance.now() - at;
    }
  };
  let result;
  try {
    try {
      result = await request();
    } catch (initialError) {
      // Only retry failures that prove the POST never reached the server.
      // Timeouts, connection resets, HTTP errors and malformed responses may
      // follow an already-applied profile/recovery update; never replay those.
      const code = initialError?.cause?.code ?? initialError?.code;
      if (controller.signal.aborted || !backendService || !["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"].includes(code)) throw initialError;
      const at = performance.now();
      let ready;
      try { ready = await bounded(backendService.ensureReady()); }
      finally { timings.recovery_ms = performance.now() - at; }
      if (!ready) throw initialError;
      result = await request();
    }
  } catch (error) {
    const failClosed = config.failClosed !== false;
    result = {
      gate_action: failClosed ? "block" : "allow", allowed: !failClosed,
      message: `AgentMeter-Gov unavailable; ${failClosed ? "fail closed" : "fail open is enabled"}: ${String(error?.message ?? error)}`,
      risk_measurement: { total_score: failClosed ? 100 : 50,
        matched_rules: failClosed ? ["R-FAIL-CLOSED：风险闸门不可用，按安全策略阻断"] : [] },
    };
    timings.error_kind = controller.signal.aborted ? "timeout" : "request_failed";
  } finally {
    clearTimeout(timer);
  }
  return { ...result, gate_transport: { ...timings, total_ms: performance.now() - started } };
}
