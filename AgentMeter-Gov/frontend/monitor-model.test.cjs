"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const M = require("./monitor-model.js");

const now = Date.parse("2026-09-10T01:00:00Z");
const timestamp = delta => new Date(now + delta).toISOString();
const risk = fields => ({ event_type: "risk_decision_event", ...fields });
const result = fields => ({ event_type: "result_event", ...fields });

test("an unmarked event cannot inherit a sibling's explicit live provenance", () => {
  const unknown = { event_id: "E-unknown" };
  const live = { event_id: "E-live", source_kind: "live" };
  const task = { adapter: "openclaw", task_id: "openclaw-live-1", events: [live, unknown] };
  assert.equal(M.source(task, unknown).kind, "unknown");
  assert.equal(M.source(task, live).kind, "live");
  assert.equal(M.source(task).kind, "unknown");
});

test("source classifications honor explicit task context and archive wrappers", () => {
  assert.equal(M.source({ source_kind: "live" }, {}).kind, "live");
  assert.equal(M.source({ source_kind: "live" }, { source_kind: "historical" }).kind, "history");
  const archive = { source_kind: "historical", is_test: true, origin_file: "data/example.json" };
  assert.equal(M.source(archive, { source_kind: "live" }).kind, "test");
  assert.match(M.source(archive).detail, /历史归档测试记录/);
  assert.equal(M.source({ events: [{ source_kind: "live" }, { source_kind: "live" }] }).kind, "live");
  assert.equal(M.source({ events: [{ source_kind: "live" }, { is_test: true }] }).kind, "unknown");
});

test("normalization preserves missing backend IDs and does not turn archive generation into event time", () => {
  const original = { run_id: "R-1", record_generated_at: timestamp(-1000), summary_only: true, events: [] };
  const task = M.normalizeTasks([original])[0];
  assert.equal(task.task_id, null);
  assert.equal(task.task_key, "R-1");
  assert.equal(task.started_at, "");
  assert.equal(task.ended_at, "");
  assert.equal(task.last_event_at, "");
  assert.equal(task.events.length, 0);
  assert.deepEqual(original, { run_id: "R-1", record_generated_at: timestamp(-1000), summary_only: true, events: [] });
});

test("block recommendations remain separate from recorded security decisions", () => {
  const summary = { summary_only: true, risk_summary: { score: 42, action: "block", matched_rules: ["HARD-BLOCK"] } };
  assert.equal(M.taskState(summary).code, "block_recommendation");
  assert.equal(M.riskEvents(summary)[0].summary_only, true);
  assert.equal(M.riskEvents(summary)[0].event_id, null);
  assert.equal(M.riskEvents(summary)[0].timestamp, "");
  assert.equal(M.execution(summary).confirmed, false);
  const recorded = { events: [risk({ gate_action: "block", risk_score: 42, triggered_rules: ["HARD-BLOCK"] })] };
  assert.equal(M.taskState(recorded).code, "blocked");
  assert.equal(M.execution(recorded).confirmed, false);
});

test("a model refusal does not become a safety-layer block or a scored risk", () => {
  const task = { enforcement_layer: "model_refusal_before_tool", observed: "block", passed: true, events: [] };
  assert.equal(M.taskState(task).code, "model_refused");
  assert.equal(M.execution(task).status, "model_refused");
  assert.equal(M.execution(task).confirmed, false);
  assert.deepEqual(M.riskEvents(task), []);
});

test("raw review requests and approval events do not invent a reconciled current state", () => {
  const task = { events: [
    { event_type: "pending_review_event", review_id: "AGR-1", timestamp: timestamp(-2000), call_id: "CALL-1" },
    { event_type: "approval_event", review_id: "AGR-1", approval_id: "APP-1", review_decision: "approve", timestamp: timestamp(-1000) }
  ] };
  const review = M.reviews(task)[0];
  assert.equal(review.review_id, "AGR-1");
  assert.equal(review.request_status, "pending");
  assert.equal(review.status, "unprovided");
  assert.equal(review.execution_status, "unprovided");
  assert.equal(M.taskState(task).code, "review_unconfirmed");
});

test("backend reconciliation remains per request and one approval cannot complete the task", () => {
  const task = { reviews: [
    { review_id: "AGR-1", state: "approved", request_event: { call_id: "CALL-1" }, resolution_event: { reviewer: "reviewer-1", comment: "ok" } },
    { review_id: "AGR-2", state: "pending", request_event: { call_id: "CALL-2" } }
  ], events: [result({ execution_result: "success" })] };
  const reviews = M.reviews(task);
  assert.equal(reviews[0].status, "approved");
  assert.equal(reviews[0].reviewer, "reviewer-1");
  assert.equal(reviews[0].execution_status, "unprovided");
  assert.equal(reviews[1].status, "pending");
  assert.equal(M.taskState(task).code, "awaiting_review");
  assert.equal(M.taskState({ reviews: [reviews[0]], events: [] }).code, "approved_awaiting_retry");
});

test("approval grant IDs cannot be substituted for missing request IDs", () => {
  assert.equal(M.reviews({ reviews: [{ approval_id: "APP-grant", status: "pending" }] })[0].review_id, null);
  assert.equal(M.reviews({ reviews: [{ approval_id: "AGR-legacy", status: "pending" }] })[0].review_id, "AGR-legacy");
  const summary = { risk_summary: { gate_action: "human_review", risk_score: 54 } };
  assert.equal(M.reviews(summary)[0].status, "unprovided");
  assert.equal(M.reviews(summary)[0].review_id, null);
});

test("agent completion, successful receipt, failed receipt and a tool failure stay distinct", () => {
  const completed = { events: [result({ execution_result: "completed" })] };
  assert.equal(M.execution(completed).status, "agent_completed");
  assert.equal(M.execution(completed).confirmed, false);
  assert.equal(M.execution({ status: "completed", events: [result({})] }).confirmed, false);
  assert.equal(M.execution({ events: [result({ execution_result: "success" })] }).confirmed, true);
  assert.equal(M.execution({ events: [result({ execution_result: "FAILED" })] }).status, "failed");
  assert.equal(M.execution({ events: [{ event_type: "tool_event", status: "failed" }] }).confirmed, false);
  const cancelled = { events: [result({ execution_result: "cancelled" })] };
  assert.equal(M.taskState(cancelled).code, "not_executed");
  assert.notEqual(M.taskState(cancelled).code, "blocked");
});

test("freshness uses explicit last event time and never treats missing or future times as active", () => {
  const [fresh] = M.normalizeTasks([{ status: "running", last_event_at: timestamp(-1000), events: [] }]);
  assert.equal(fresh.ended_at, timestamp(-1000));
  assert.equal(M.taskState(fresh, now).code, "running");
  assert.equal(M.taskState({ status: "running", last_event_at: timestamp(-180001) }, now).code, "incomplete");
  assert.equal(M.taskState({ status: "running" }, now).code, "unknown");
  assert.equal(M.taskState({ status: "running", last_event_at: timestamp(1000) }, now).code, "unknown");
  assert.equal(M.taskState({ status: "running", last_event_at: timestamp(-1000), ended_at: timestamp(-900000) }, now).code, "running");
});

test("nine-factor details preserve zero and missing values without estimating from rules", () => {
  const rows = M.factors({ risk_score: 92, triggered_rules: ["R-09"], factor_contributions: {
    D: { score: 0, weight: 0.18, contribution: 0 }, C: { score: 80, weight: 0.1, contribution: 8 }
  } });
  assert.equal(rows.length, 9);
  assert.deepEqual(rows.map(row => row.code), ["C", "G", "D", "P", "T", "S", "A", "I", "U"]);
  assert.equal(rows.find(row => row.code === "D").score, 0);
  assert.equal(rows.find(row => row.code === "D").contribution, 0);
  assert.equal(rows.find(row => row.code === "G").score, null);
  assert.equal(rows.find(row => row.code === "G").weight, null);
});

test("five audit dimensions use the canonical order and recorded-weight normalization", () => {
  const factor_contributions = {
    C: { score: 20, weight: .10, contribution: 2 }, G: { score: 10, weight: .12, contribution: 1.2 },
    D: { score: 0, weight: .18, contribution: 0 }, P: { score: 50, weight: .10, contribution: 5 },
    T: { score: 70, weight: .13, contribution: 9.1 }, S: { score: 80, weight: .08, contribution: 6.4 },
    A: { score: 20, weight: .09, contribution: 1.8 }, I: { score: 40, weight: .12, contribution: 4.8 },
    U: { score: 30, weight: .08, contribution: 2.4 }
  };
  const rows = M.dimensions({ factor_contributions });
  assert.deepEqual(rows.map(row => row.name), ["数据安全", "内容安全", "执行安全", "供应链安全", "合规风险"]);
  assert.deepEqual(rows.map(row => row.factor_codes), [["D"], ["C", "I"], ["P", "T"], ["S"], ["G", "A", "U"]]);
  assert.deepEqual(rows.map(row => row.score), [0, 30.91, 61.3, 80, 18.62]);
  assert(rows.every(row => row.complete));
});

test("a five-dimensional score stays missing when any mapped score or weight is absent", () => {
  const rows = M.dimensions({ factor_contributions: {
    C: { score: 0, weight: .1 }, I: { score: 10 }, D: { score: 0, weight: .18 }
  } });
  assert.equal(rows.find(row => row.code === "data").score, 0);
  assert.equal(rows.find(row => row.code === "content").score, null);
  assert.equal(rows.find(row => row.code === "content").complete, false);
  assert.equal(rows.find(row => row.code === "execution").score, null);
});

test("a low-risk allow decision remains a visible scored metrology record", () => {
  const allowed = risk({ gate_action: "allow", risk_score: 6, factor_contributions: {
    C: { score: 10, weight: .10 }, G: { score: 8, weight: .12 }, D: { score: 10, weight: .18 },
    P: { score: 5, weight: .10 }, T: { score: 10, weight: .13 }, S: { score: 5, weight: .08 },
    A: { score: 5, weight: .09 }, I: { score: 0, weight: .12 }, U: { score: 0, weight: .08 }
  } });
  const rows = M.riskEvents({ events: [allowed] });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].risk_score, 6);
  assert.equal(M.dimensions(rows[0]).filter(item => item.complete).length, 5);
});

test("default snapshot omits backend freeform fields even when named safe_summary", () => {
  const task = { task_id: "T-1", title: "private-title", goal: "private-goal", safe_summary: {
    title: "private-summary-title", goal: "private-summary-goal", risk: "private-summary-risk"
  }, reviews: [{ review_id: "AGR-1", status: "approved", reviewer: "private-reviewer", comment: "private-comment" }],
  events: [risk({ gate_action: "human_review", risk_score: 54, evidence: "private-evidence", parameters: { credential: "private-credential" } })] };
  const snapshot = M.snapshot([task]);
  assert.equal(snapshot.tasks[0].title, "T-1");
  assert(!JSON.stringify(snapshot).includes("private-"));
  assert.equal(snapshot.signed, false);
  assert.equal(snapshot.integrity.audit_signature_verified, false);
  assert.equal(snapshot.schema_version, "agentmeter.monitoring-snapshot.v2");
  assert.equal(snapshot.export_summary.exported_task_count, 1);
  assert.equal(snapshot.tasks[0].events[0].dimensions, undefined);
  assert.equal(snapshot.tasks[0].risk_records[0].dimensions, undefined);
});

test("real plugin semantic and government rule IDs survive the redacted snapshot", () => {
  const task = { task_id: "T-rules", events: [risk({ gate_action: "human_review", risk_score: 40,
    triggered_rules: [
      "SEM-R-01：private-semantic-evidence",
      "GOV-AUTH-SCOPE-01：private-authorization-evidence",
      "R-04 private-rule-evidence",
      "HARD-BLOCK：private-block-evidence",
      { rule_id: "SEM-I-01", description: "private-intent-evidence" },
      { code: "GOV-BIZ-STATE-01" }, null,
      "R-04-private-content", "private-freeform-evidence"
    ] })] };
  const snapshot = M.snapshot([task]);
  const expected = ["SEM-R-01", "GOV-AUTH-SCOPE-01", "R-04", "HARD-BLOCK", "SEM-I-01", "GOV-BIZ-STATE-01"];
  assert.deepEqual(snapshot.tasks[0].events[0].rule_ids, expected);
  assert.deepEqual(snapshot.tasks[0].risk_records[0].rule_ids, expected);
  assert(!JSON.stringify(snapshot).includes("private-"));
  assert.equal(M.ruleId("SEM-R-01：evidence"), "SEM-R-01");
  assert.equal(M.ruleId("R-04-unrecognized-suffix"), null);
});

test("snapshot separates exported count from available count and omits empty repeated measurements", () => {
  const task = { task_id: "T-compact", events: [
    { event_type: "input_event", event_id: "E-input", user_goal: "private" },
    risk({ event_id: "E-risk", gate_action: "allow", risk_score: 10,
      factor_contributions: { A: { score: 10, weight: .09, contribution: .9 } } })
  ] };
  const snapshot = M.snapshot([task], { total: 40 });
  assert.deepEqual(snapshot.export_summary, {
    exported_task_count: 1,
    available_task_count_at_export: 40,
    note: "本文件只包含已勾选任务；可选任务数仅用于说明导出时的页面范围。"
  });
  assert.equal(snapshot.integrity.backend_total, undefined);
  assert.equal(snapshot.tasks[0].events[0].factors, undefined);
  assert.equal(snapshot.tasks[0].events[0].dimensions, undefined);
  assert.equal(snapshot.tasks[0].risk_records[0].factors.length, 1);
});

test("actual business output needs a matching successful write receipt", () => {
  const task = { execution_mode: "actual_local_openclaw", business_outcome: { summary_created: true, output_written_event_id: "WRITE-1" },
    events: [{ event_type: "result_event", execution_result: "completed" }] };
  assert.equal(M.execution(task).confirmed, false);
  task.events.push({ event_type: "tool_event", event_id: "OTHER", status: "success" });
  assert.equal(M.execution(task).confirmed, false);
  task.events.push({ event_type: "tool_event", event_id: "WRITE-1", tool_name: "write_file", status: "failed" });
  assert.equal(M.execution(task).confirmed, false);
  task.events.at(-1).status = "success";
  assert.equal(M.execution(task).label, "办理产物已生成");
  assert.equal(M.execution(task).confirmed, true);
});

test("refusal of the target operation retains earlier read receipts", () => {
  const task = { enforcement_layer: "model_refusal_before_target_tool", events: [{ event_type: "tool_event", tool_name: "read_document", status: "success" }] };
  assert.equal(M.execution(task).label, "模型未申请目标修改");
  assert.equal(M.execution(task).receipts.length, 1);
  assert.equal(M.taskState(task).code, "model_refused");
});

test("explicit archive context permits reviewed summaries while continuing to redact identifiers", () => {
  const task = { task_id: "T-1", safe_summary: { title: "归档案例", goal: "联系 demo@example.org", risk: "手机号 13812345678" }, events: [] };
  const snapshot = M.snapshot([task], { includeReviewedArchiveSummaries: true });
  assert.equal(snapshot.tasks[0].title, "归档案例");
  assert.match(snapshot.tasks[0].goal, /邮箱已脱敏/);
  assert.match(snapshot.tasks[0].risk_reason, /手机号已脱敏/);
  assert(!JSON.stringify(snapshot).includes("demo@example.org"));
});

test("the production monitor loads only live backend data", () => {
  const html = fs.readFileSync(path.join(__dirname, "security-layer.html"), "utf8");
  const app = fs.readFileSync(path.join(__dirname, "security-layer.js"), "utf8");
  assert(!html.includes("preview-data.js"));
  assert(!html.includes("live-run.json"));
  assert(!app.includes("M.normalizeTasks(PREVIEW_DATA)"));
  assert.match(app, /mode:'backend',tasks:\[\]/);
  assert.match(app, /state\.monitoringScope='current'/);
  assert.match(app, /'\?scope='\+state\.monitoringScope/);
  assert(!html.includes("security-layer-legacy"));
  assert(!app.includes("六维"));
  assert(!html.includes("datasetMode"));
  assert(!html.includes("headerExport"));
  assert(!html.includes("connectionBanner"));
  assert(!app.includes("流程演示"));
  assert(!app.includes("插件活动已过期"));
  assert(!app.includes("'安全策略'"));
  assert.match(app, /overviewRadar/);
  assert(!app.includes('data-action="record-scope"'));
  assert.match(app, /class="direct-filter"/);
  assert(!app.includes('data-action="clear-advanced-filters"'));
  assert.match(app, /本次开机累计/);
  assert.match(app, /记录来源/);
  assert(!app.includes("(advanced?'open':'')"));
  assert.match(app, /技术详情（供专业人员核对）/);
  assert.match(app, /异常或记录不完整/);
  assert(!app.includes("模型未继续执行"));
  assert.match(app, /detailStates\(root\)/);
  assert.match(app, /previousSignature!==pageDataSignature\(\)/);
  assert.match(app, /state\.selected=new Set\(\[\.\.\.state\.selected\]\.filter/);
  assert(!app.includes("state.selected=new Set(state.tasks.map"));
  assert.match(app, /打印所选档案/);
  assert.match(app, /导出所选档案/);
  assert(!app.includes("setInterval(()=>{if(state.mode==='backend'"));
  assert.match(app, /文件内任务数/);
  assert.equal(fs.existsSync(path.join(__dirname, "security-layer-legacy.html")), false);
  assert.equal(fs.existsSync(path.join(__dirname, "security-layer-legacy.js")), false);
  assert.equal(fs.existsSync(path.join(__dirname, "security-layer-legacy.css")), false);
});

test("history is explicitly selected, read-only and not polled as live data", () => {
  const html = fs.readFileSync(path.join(__dirname, "security-layer.html"), "utf8");
  const app = fs.readFileSync(path.join(__dirname, "security-layer.js"), "utf8");
  assert.match(html, /id="monitoringScope"/);
  assert.match(html, /value="current" selected>本次开机/);
  assert.match(html, /value="history">历史记录/);
  assert.match(app, /if\(viewingHistory\(\)&&!forceRender\)return/);
  assert.match(app, /state\.mode==='backend'&&!viewingHistory\(\)&&!state\.error/);
  assert.match(app, /state\.monitoringScope=scope;state\.requestId\+\+;state\.loading=false/);
  assert.match(app, /历史记录（全部已保存，含本次开机）/);
  assert(!app.includes("localStorage.setItem('monitoringScope'"));
});
