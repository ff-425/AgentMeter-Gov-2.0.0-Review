(function (root) {
  "use strict";
  function expandTaskPayload(payload) {
    if (!payload?.transport) return payload; // Existing backends keep the full response.
    if (payload.transport !== "task-events-v1" || !Array.isArray(payload.tasks) ||
        !Array.isArray(payload.decision_refs) || payload.decision_refs.length !== payload.tasks.length ||
        !payload.event_defaults || typeof payload.event_defaults !== "object" || Array.isArray(payload.event_defaults)) {
      throw new Error("任务响应格式异常");
    }
    const { transport, event_defaults, decision_refs, ...rest } = payload;
    return { ...rest, tasks: payload.tasks.map((task, index) => {
      if (!Array.isArray(task.events) || !Array.isArray(decision_refs[index]) || decision_refs[index].length !== 2) {
        throw new Error("任务响应格式异常");
      }
      const events = task.events.map(event => {
        if (!event || typeof event !== "object" || Array.isArray(event)) throw new Error("任务响应格式异常");
        return { ...event_defaults, ...event };
      });
      const resolve = position => {
        if (position === null) return null;
        if (!Number.isInteger(position) || position < 0 || position >= events.length) throw new Error("任务响应格式异常");
        return events[position];
      };
      return { ...task, events, latest_decision: resolve(decision_refs[index][0]), peak_decision: resolve(decision_refs[index][1]) };
    }) };
  }
  const definitions = [
    ["C", "来源与上下文风险"], ["G", "目标偏移风险"], ["D", "数据风险"],
    ["P", "权限放大风险"], ["T", "工具链组合风险"], ["S", "插件 / Skill 供应链风险"],
    ["A", "审计与行为异常风险"], ["I", "意图偏移风险"], ["U", "用户习性偏移风险"]
  ].map(([code, name]) => ({ code, name }));
  const dimensionDefinitions = [
    ["data", "数据安全", ["D"]],
    ["content", "内容安全", ["C", "I"]],
    ["execution", "执行安全", ["P", "T"]],
    ["supply_chain", "供应链安全", ["S"]],
    ["compliance", "合规风险", ["G", "A", "U"]]
  ].map(([code, name, factorCodes]) => ({ code, name, factor_codes: factorCodes }));
  const list = value => Array.isArray(value) ? value : [];
  const present = value => value !== undefined && value !== null && value !== "";
  const number = value => typeof value === "number" && Number.isFinite(value) ? value : null;
  const text = value => present(value) ? String(value) : "";
  const identifier = value => /^[A-Za-z0-9_.:@/-]{1,180}$/.test(text(value)) ? text(value) : null;
  const actionOf = event => event?.gate_action || event?.decision || event?.action || "";
  const eventTime = event => text(event?.timestamp);
  const validTime = value => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value) && Number.isFinite(Date.parse(value));
  const toolOf = event => event?.proposed_tool_call?.name || event?.tool_name || event?.control_plan?.current_tool || "";
  const ruleId = rule => {
    const value = rule && typeof rule === "object" ? rule.rule_id || rule.code : rule;
    return text(value).match(/^\s*(HARD-BLOCK|(?:[A-Z][A-Z0-9]*-)+\d+)(?=$|[\s:：,，;；])/)?.[1] || null;
  };

  function source(task, event) {
    const kind = item => item.source_kind || item.provenance?.kind || item.data_source?.kind;
    const classify = item => !item ? "unknown" : item.is_test === true || item.synthetic === true ||
      ["test", "synthetic", "sample", "demo"].includes(kind(item)) ? "test" :
      ["historical", "history", "replay"].includes(kind(item)) ? "history" :
      ["live", "realtime", "real_time"].includes(kind(item)) ? "live" : "unknown";
    const own = classify(task), specific = classify(event);
    let resolved = own;
    if (event) {
      // Archive/test context still applies to an event originally collected live.
      resolved = own === "test" ? own : own === "history" && specific !== "test" ? own : specific !== "unknown" ? specific : own;
    } else if (own === "unknown") {
      const children = list(task?.events).map(classify);
      resolved = children.length && children.every(child => child === children[0]) ? children[0] : "unknown";
    }
    const historical = [task, event].filter(Boolean).some(item => ["historical", "history", "replay"].includes(kind(item)));
    const origin = text(event?.origin_file || task?.origin_file);
    if (resolved === "test") return { kind: "test", label: "测试数据", detail: (historical ? "历史归档测试记录" : "明确标记的测试记录") + (origin ? " · " + origin : "") };
    if (resolved === "history") return { kind: "history", label: "历史回放", detail: "历史记录，不代表当前运行" + (origin ? " · " + origin : "") };
    if (resolved === "live")
      return { kind: "live", label: "实时运行", detail: "来源由上游显式标记；在线状态需另行核验" };
    return { kind: "unknown", label: "来源未知", detail: "接口路径、任务名称或 adapter 均不能证明数据来源" };
  }

  function normalizeTasks(payload) {
    const rows = Array.isArray(payload) ? payload : list(payload?.tasks);
    return rows.filter(item => item && typeof item === "object" && !Array.isArray(item)).map((item, index) => {
      const events = list(item.events).filter(event => event && typeof event === "object" && !Array.isArray(event))
        .map(event => ({ ...event })).sort((a, b) => (Date.parse(eventTime(a)) || 0) - (Date.parse(eventTime(b)) || 0));
      const inputs = events.filter(event => event.event_type === "input_event" && present(event.user_goal));
      const goal = item.goal || item.user_goal || inputs.at(-1)?.user_goal || "";
      const scores = events.filter(event => event.event_type === "risk_decision_event").map(event => number(event.risk_score)).filter(present);
      const summaryScore = number(item.risk_summary?.risk_score ?? item.risk_summary?.score ?? item.risk_score ?? item.score);
      return {
        ...item,
        task_id: item.task_id || null,
        task_key: item.task_key || item.task_id || item.run_id || item.case_id || "preview-row-" + index,
        title: item.title || item.safe_summary?.title || (goal ? text(goal).slice(0, 48) : "未命名任务记录"),
        goal,
        events,
        started_at: item.started_at || events.find(event => validTime(event.timestamp))?.timestamp || "",
        ended_at: item.ended_at || item.last_event_at || events.filter(event => validTime(event.timestamp)).at(-1)?.timestamp || "",
        last_event_at: item.last_event_at || events.filter(event => validTime(event.timestamp)).at(-1)?.timestamp || item.ended_at || "",
        record_generated_at: item.record_generated_at || "",
        max_risk_score: [...scores, number(item.max_risk_score), summaryScore].filter(present).length
          ? Math.max(...[...scores, number(item.max_risk_score), summaryScore].filter(present)) : null,
        event_count: number(item.event_count) ?? events.length,
        tools: list(item.tools).length ? item.tools : [...new Set(events.map(toolOf).filter(Boolean))],
        targets: list(item.targets).length ? item.targets : [...new Set(events.map(event => event.target).filter(Boolean))]
      };
    });
  }

  function riskEvents(task) {
    // Every gate decision is a metrology record. Low-risk allow decisions must
    // remain visible instead of disappearing from the risk workspace.
    const found = list(task?.events).filter(event => event.event_type === "risk_decision_event")
      .map(event => ({ ...event, summary_only: false, tool_name: toolOf(event) || event.tool_name }));
    if (found.length) return found;
    const summary = task?.risk_summary;
    if (!summary || task?.enforcement_layer === "model_refusal_before_tool") return [];
    return [{ ...summary, summary_only: true, event_id: summary.event_id || null, timestamp: summary.timestamp || "",
      event_type: "risk_summary", tool_name: toolOf(summary), risk_score: number(summary.risk_score ?? summary.score),
      gate_action: actionOf(summary), triggered_rules: list(summary.triggered_rules || summary.matched_rules),
      evidence: summary.evidence || "原文件仅提供评测 / 处置摘要，没有逐事件回执。" }];
  }

  function taskRisk(task) {
    const records = riskEvents(task);
    const rank = { allow: 1, human_review_approved: 1, human_review: 2, block: 3, deny: 3 };
    const decision = records.reduce((best, event) =>
      (rank[actionOf(event)] || 0) > (rank[actionOf(best)] || 0) ? event : best, null);
    const scores = [number(task?.max_risk_score), ...records.map(event => number(event.risk_score))].filter(present);
    return { score: scores.length ? Math.max(...scores) : null, decision };
  }

  function factors(event) {
    const contributions = event?.factor_contributions || event?.scoring_details?.factor_contributions || {};
    return definitions.map(def => {
      const item = contributions[def.code] || list(event?.factors).find(row => row.code === def.code) || {};
      return { ...def, score: number(item.score), weight: number(item.weight),
        contribution: number(item.contribution ?? item.weighted_score ?? item.weighted_contribution),
        evidence: list(item.evidence), definition: item.definition || "" };
    });
  }

  function dimensions(event) {
    const byCode = new Map(factors(event).map(factor => [factor.code, factor]));
    return dimensionDefinitions.map(def => {
      const members = def.factor_codes.map(code => byCode.get(code));
      const complete = members.every(item => item && item.score !== null && item.weight !== null);
      const totalWeight = complete ? members.reduce((sum, item) => sum + item.weight, 0) : null;
      const score = complete && totalWeight > 0
        ? Number((members.reduce((sum, item) => sum + item.score * item.weight, 0) / totalWeight).toFixed(2))
        : null;
      const contribution = members.every(item => item && item.contribution !== null)
        ? Number(members.reduce((sum, item) => sum + item.contribution, 0).toFixed(4))
        : null;
      return { ...def, score, contribution, complete };
    });
  }

  function reviews(task) {
    const supplied = list(task?.reviews).filter(review => review && typeof review === "object" && !Array.isArray(review));
    if (supplied.length) return supplied.map(review => {
      const request = review.request_event || review;
      const resolution = review.resolution_event || {};
      return { ...review,
        review_id: review.review_id || request.review_id || (text(request.approval_id).startsWith("AGR-") ? request.approval_id : null),
        status: review.state || review.status || "unprovided",
        reviewer: review.reviewer || resolution.reviewer || resolution.approver || null,
        comment: review.comment || resolution.comment || resolution.review_comment || null,
        requested_at: review.requested_at || review.created_at || request.timestamp || null,
        expires_at: review.expires_at || resolution.expires_at || null,
        tool_request_id: review.tool_request_id || request.call_id || request.tool_call_id || request.operation_id || null,
        tool_name: review.tool_name || toolOf(request) || null,
        impact: review.impact ?? request.target ?? task?.affected_record_count ?? null,
        execution_status: review.execution_status || "unprovided",
        request_event: request, resolution_event: review.resolution_event || null };
    });
    const requests = list(task?.events).filter(event => event.event_type === "pending_review_event");
    if (requests.length) return requests.map(request => ({ review_id: request.review_id ||
      (text(request.approval_id).startsWith("AGR-") ? request.approval_id : null), status: "unprovided", request_status: "pending",
      reviewer: null, comment: null, requested_at: request.timestamp || null, expires_at: null,
      tool_request_id: request.call_id || request.tool_call_id || request.operation_id || null,
      tool_name: toolOf(request) || null, execution_status: "unprovided", request_event: request,
      detail: "仅有审批申请事件；未提供后端逐项汇总的当前状态，不能确认是否仍待复核。" }));
    const decisions = riskEvents(task).filter(event => actionOf(event) === "human_review");
    return decisions.map(request => ({ review_id: request.review_id || null, status: "unprovided",
      reviewer: null, comment: null, requested_at: request.timestamp || null, expires_at: null,
      tool_request_id: request.call_id || request.tool_call_id || request.operation_id || null,
      tool_name: toolOf(request) || null, impact: task?.affected_record_count || null,
      execution_status: "unprovided", request_event: request,
      detail: "记录要求人工复核；审批请求及最终状态未提供。" }));
  }

  function execution(task) {
    const events = list(task?.events);
    const receipts = events.filter(event => event.event_type === "tool_event" || event.event_type === "result_event");
    const final = receipts.filter(event => event.event_type === "result_event").at(-1);
    if (task?.enforcement_layer === "model_refusal_before_target_tool") return { status: "model_refused", label: "模型未申请目标修改",
      confirmed: false, detail: "已记录材料读取；模型公开回复拒绝发起目标修改，未记录该修改的工具请求或插件阻断。", receipts };
    const business = task?.business_outcome;
    const outputReceipt = events.find(event => event.event_id === business?.output_written_event_id && event.event_type === "tool_event" && event.status === "success"
      && ["write", "write_file", "edit", "apply_patch", "exec", "run_shell"].includes(toolOf(event)));
    if (task?.execution_mode === "actual_local_openclaw" && business?.summary_created === true && outputReceipt)
      return { status: "success", label: "办理产物已生成", confirmed: true, detail: "本次输出文件与成功写入回执已核对；不代表原项目已通过验收。", receipts };
    if (task?.enforcement_layer === "model_refusal_before_tool") return { status: "model_refused", label: "模型在工具调用前拒绝",
      confirmed: false, detail: "验收摘要标注为模型拒绝；未提供工具执行回执，不能归入安全层阻断。", receipts };
    const outcome = text(final?.execution_result || final?.status).toLowerCase();
    if (["failed", "error"].includes(outcome)) return { status: "failed", label: "执行失败", confirmed: true,
      detail: final.execution_error ? "OpenClaw 执行失败：" + text(final.execution_error) : text(final.evidence) || "后端结果事件报告失败。", receipts };
    if (outcome === "success") return { status: "success", label: "结果事件报告成功", confirmed: true, detail: "按后端结果回执展示，具体业务对象结果需核对。", receipts };
    if (outcome === "completed") return { status: "agent_completed", label: "任务结束，业务结果需核对", confirmed: false,
      detail: "收到 agent_end 完成记录；完成事件不等于所有工具或业务操作成功。", receipts };
    if (["blocked", "denied", "cancelled", "canceled", "aborted"].includes(outcome)) return { status: "not_executed", label: "结果报告未执行",
      confirmed: true, detail: "后端结果状态为 " + outcome + "；该状态本身不能证明由安全层阻断。", receipts };
    if (task?.file_unchanged_before_approval === true) return { status: "awaiting_review", label: "审批前文件保持不变", confirmed: false,
      detail: "归档测试记录确认审批前未修改；审批后的执行结果未提供。", receipts };
    return { status: "unprovided", label: "执行结果未提供", confirmed: false,
      detail: receipts.length ? "仅有工具活动记录，未提供任务最终业务结果。" : "放行、阻断建议或评测 passed 均不等于业务执行成功。", receipts };
  }

  function taskState(task, now = Date.now()) {
    const make = (code, label, tone, detail) => ({ code, label, tone, detail });
    if (task?.enforcement_layer === "model_refusal_before_target_tool") return make("model_refused", "模型自行拒绝", "neutral", "模型读取材料后拒绝申请目标修改，未发生该修改的插件阻断。");
    if (task?.enforcement_layer === "model_refusal_before_tool") return make("model_refused", "模型自行拒绝", "neutral", "验收摘要归因为模型拒绝，非安全层阻断。");
    const pending = reviews(task);
    if (pending.some(review => review.status === "pending")) return make("awaiting_review", "待复核", "warning", "审批状态按后端记录展示。");
    if (pending.some(review => review.status === "unprovided")) return make("review_unconfirmed", "复核状态待确认", "warning", "已记录复核要求；请求编号或最终状态未提供。");
    if (pending.some(review => ["approved", "approved_waiting_retry"].includes(review.status))) return make("approved_awaiting_retry", "已批准，待执行确认", "warning", "审批通过不等于已执行。");
    if (pending.some(review => review.status === "rejected")) return make("review_rejected", "已拒绝", "danger", "收到后端拒绝状态。");
    const blocks = riskEvents(task).filter(event => ["block", "deny"].includes(actionOf(event)));
    if (blocks.some(event => !event.summary_only)) return make("blocked", "已记录阻断", "danger", "安全层记录了阻断；其他工具结果需逐项查看。");
    if (blocks.length) return make("block_recommendation", "阻断判定摘要", "warning", "仅有引擎判定摘要；未提供实际工具回执，不能确认阻断已执行。");
    const result = execution(task);
    if (result.status === "failed") return make("failed", "执行失败", "danger", result.detail);
    if (result.status === "success") return make("completed", "结果报告成功", "success", result.detail);
    if (result.status === "agent_completed") return make("completed", "任务已结束", "neutral", result.detail);
    if (result.status === "not_executed") return make("not_executed", "结果报告未执行", "neutral", result.detail);
    if (task?.status === "running") {
      const latest = Date.parse(task.last_event_at || eventsLastTime(task) || task.ended_at);
      if (!Number.isFinite(latest)) return make("unknown", "运行进度待确认", "neutral", "后端标记运行中，但最近事件时间未提供。");
      if (latest > Number(now)) return make("unknown", "事件时间待核对", "neutral", "最近事件时间晚于当前时间，不能确认运行进度。");
      if (Number(now) - latest > 180000) return make("incomplete", "长时间无新事件", "neutral", "超过 180 秒未收到新事件，当前进度待确认。");
      return make("running", "正在运行", "info", "后端标记运行中且最近 180 秒内有事件。");
    }
    if (task?.status === "failed") return make("failed", "后端报告执行失败", "danger", "按任务状态显示；详细执行回执需另行核对。");
    if (task?.status === "awaiting_review") return make("awaiting_review", "待复核", "warning", "后端任务状态为待复核；审批明细需另行核对。");
    if (task?.status === "approved_awaiting_retry") return make("approved_awaiting_retry", "已批准，待执行确认", "warning", "后端任务状态表明已批准；执行回执未提供。");
    if (task?.status === "review_rejected") return make("review_rejected", "已拒绝", "danger", "按后端任务状态展示。");
    if (task?.status === "blocked") return make("blocked", "后端报告阻断", "danger", "按后端任务状态展示；对应决策事件需另行核对。");
    if (task?.status === "completed") return make("completed", "后端报告任务结束", "neutral", "任务状态为完成；具体业务执行回执需另行核对。");
    if (task?.status === "incomplete") return make("incomplete", "长时间无新事件", "neutral", "未收到最终结果。");
    return make("unknown", "结果待确认", "neutral", "现有字段不足以确认任务最终结果。");
  }
  function eventsLastTime(task) { return list(task?.events).at(-1)?.timestamp || ""; }

  function redact(value) {
    return text(value)
      .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [已脱敏]")
      .replace(/\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b/g, "[密钥已脱敏]")
      .replace(/((?:api[_-]?key|access[_-]?token|secret|password|authorization|密码|密钥)\s*[=:：]\s*)[^\s,;]+/gi, "$1[已脱敏]")
      .replace(/\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g, "[身份证号已脱敏]")
      .replace(/\b1[3-9]\d{9}\b/g, "[手机号已脱敏]")
      .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[邮箱已脱敏]")
      .replace(/([A-Za-z]:[\\/]Users[\\/])[^\\/\s]+/g, "$1[用户]");
  }

  function snapshot(tasks, context = {}) {
    const safeText = value => present(value) ? redact(value).slice(0, 800) : null;
    const reviewedSummary = task => context.includeReviewedArchiveSummaries === true ? task.safe_summary : null;
    const compact = record => Object.fromEntries(Object.entries(record).filter(([, value]) => value !== null && value !== undefined && value !== "" && (!Array.isArray(value) || value.length)));
    const structuralEvent = (event, includeMeasurement = false) => {
      const measuredFactors = includeMeasurement ? factors(event).filter(item => item.score !== null || item.weight !== null || item.contribution !== null) : [];
      const measuredDimensions = measuredFactors.length ? dimensions(event).filter(item => item.complete || item.score !== null || item.contribution !== null) : [];
      return compact({ event_id: identifier(event.event_id), event_type: identifier(event.event_type),
        timestamp: validTime(event.timestamp) ? event.timestamp : null, tool_name: identifier(toolOf(event)),
        tool_request_id: identifier(event.call_id || event.tool_call_id || event.operation_id),
        gate_action: identifier(actionOf(event)), execution_result: identifier(event.execution_result),
        status: identifier(event.status), risk_score: number(event.risk_score),
        rule_ids: list(event.triggered_rules).map(ruleId).filter(Boolean), review_id: identifier(event.review_id),
        parameters: event.parameters || event.proposed_tool_call?.params ? "已省略原始参数" : null,
        evidence: event.evidence ? "已省略自由文本证据" : null,
        factors: measuredFactors.map(({ code, name, score, weight, contribution }) => compact({ code, name, score, weight, contribution })),
        dimensions: measuredDimensions.map(({ code, name, factor_codes, score, contribution, complete }) => compact({ code, name, factor_codes, score, contribution, complete })) });
    };
    return {
      schema_version: "agentmeter.monitoring-snapshot.v2", report_type: "所选审计档案", signed: false,
      generated_at: new Date().toISOString(), base_version: identifier(context.baseVersion || "2.0.0"),
      export_summary: { exported_task_count: tasks.length, available_task_count_at_export: number(context.total),
        note: "本文件只包含已勾选任务；可选任务数仅用于说明导出时的页面范围。" },
      statistics_window: { since: validTime(context.since) ? context.since : null, until: validTime(context.until) ? context.until : null,
        label: safeText(context.rangeLabel || context.label || "当前已载入记录") },
      integrity: { scope: "当前筛选且已载入的任务", loaded_task_count: tasks.length,
        current_data_stale: context.stale === true,
        last_successful_update: validTime(context.lastSuccess) ? context.lastSuccess : null,
        audit_signature_verified: false, completeness: "仅包含当前已载入字段；未证明覆盖完整历史，也未验证审计签名。",
        redaction: "导出采用结构字段白名单；原始目标、工具参数和自由文本证据默认省略。静态测试任务仅保留人工审阅的摘要。" },
      tasks: tasks.map(task => ({ task_id: identifier(task.task_id), run_id: identifier(task.run_id), case_id: identifier(task.case_id),
        title: safeText(reviewedSummary(task)?.title) || identifier(task.task_id || task.run_id || task.case_id) || "任务记录",
        source: { kind: source(task).kind, label: source(task).label }, origin_file: safeText(task.origin_file), summary_only: task.summary_only === true,
        event_time: { first: validTime(task.started_at) ? task.started_at : null, last: validTime(task.ended_at) ? task.ended_at : null },
        archive_generated_at: validTime(task.record_generated_at) ? task.record_generated_at : null,
        goal: safeText(reviewedSummary(task)?.goal) || "未提供可安全导出的目标摘要",
        risk_reason: safeText(reviewedSummary(task)?.risk) || "参见结构化规则编号；自由文本已省略",
        system_disposition: taskState(task), execution_result: { status: execution(task).status, label: execution(task).label, confirmed: execution(task).confirmed },
        rules_version: identifier(task.rules_version || task.rule_version),
        policy_version: identifier(task.policy_version),
        reviews: reviews(task).map(review => ({ review_id: identifier(review.review_id), status: identifier(review.status),
          requested_at: validTime(review.requested_at) ? review.requested_at : null,
          expires_at: validTime(review.expires_at) ? review.expires_at : null,
          reviewer: review.reviewer ? "已提供，身份信息已省略" : null, comment: review.comment ? "已提供，原文已省略" : null,
          tool_request_id: identifier(review.tool_request_id), execution_status: identifier(review.execution_status) })),
        risk_records: riskEvents(task).map(event => structuralEvent(event, true)), events: list(task.events).map(event => structuralEvent(event, false))
      }))
    };
  }
  const api = { expandTaskPayload, normalizeTasks, source, reviews, taskState, execution, riskEvents, taskRisk, factors, dimensions,
    factorDefinitions: definitions, dimensionDefinitions, ruleId, redact, snapshot };
  root.MonitorModel = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window === "undefined" ? globalThis : window);
