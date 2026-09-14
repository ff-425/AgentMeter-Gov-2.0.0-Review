import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { rename, rm, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { guardText } from "./content-guard.js";
import { agentExecutionOutcome, toolExecutionOutcome } from "./execution-outcome.js";
import { assessInputRisk, inputRiskDecisionEvent } from "./input-risk.js";
import {
  assessMemoryOperation,
  cleanPoisonedMemoryFile,
  findActiveTaint,
  recordMemoryLineage,
  sanitizeMemoryMessage,
} from "./memory-governance.js";
import { evaluateSubagentInheritance } from "./subagent-governance.js";
import {
  finalAssistantText,
  guardPersistedToolResult,
} from "./output-governance.js";
import { registerOutputGovernanceHooks } from "./register-output-governance.js";
import {
  classifySupplyChainResult,
  componentLifecycleRequest,
  resolveSupplyChainPaths,
} from "./supply-chain-governance.js";
import { createBackendService } from "./backend-service.js";
import { requestGate } from "./gate-client.js";
import { boundaryAuditFields, classifyOperationBoundary } from "./operation-boundary.js";
import { consumeOperationBudget } from "./operation-budget.js";
import {
  approvalContinuationContext,
  bindApprovalSession,
  requestApprovedContinuation,
  selectApprovedContinuationForSession,
  selectPendingReviewForContext,
} from "./approval-routing.js";
import {
  approvalComparableParams,
  boundedTaskScopeKey,
  formatHumanReviewMessage,
  isReadOnlyOpenClawCommand,
  isReadOnlyProcessAction,
  parseApprovalCommand,
  readOnlyPublicHttpRequest,
} from "./interaction-ux.js";
import {
  analyzeEditSemantics,
  analyzeShellWriteSemantics,
  analyzeWriteSemantics,
  canonicalRuntimeToolName,
  detectHiddenInstruction,
} from "./runtime-risk.js";
import {
  extractShellDestination,
  isAuditDeleteText,
  isDestructiveShellText,
  isFileWriteShellText,
  isHarmlessShellProbeText,
  isReadOnlyShellText,
  isSensitiveWorkspaceEnumeration,
} from "./shell-classify.js";

const DEFAULT_SUPPLY_CHAIN_SCAN_URL = "http://127.0.0.1:8765/api/supply-chain/scan";
const DEFAULT_EVENT_URL = "http://127.0.0.1:8765/api/events";
const DEFAULT_RECORD_FILE = "data/openclaw_guard_flow_events.jsonl";
const DEFAULT_APPROVAL_FILE = "data/openclaw_guard_approvals.json";
const DEFAULT_REVIEW_MEMORY_FILE = "data/review_memory.json";
const DEFAULT_BATCH_STATE_FILE = "data/openclaw_guard_batch_state.json";
const DEFAULT_MEMORY_STATE_FILE = "data/memory_governance_state.json";
const DEFAULT_MEMORY_QUARANTINE_DIR = "data/memory_quarantine";
const sessionState = new Map();
const toolGovernanceContext = new Map();
const inheritedContextBySession = new Map();
const pendingSubagentInheritances = [];
let approvalStoreLock = Promise.resolve();
let batchStoreLock = Promise.resolve();
let recordStoreLock = Promise.resolve();

export default definePluginEntry({
  id: "agentmeter-gov-guard",
  name: "AgentMeter-Gov Guard",
  description: "Measure and block risky OpenClaw tool calls before execution.",
  register(api) {
    let backendService = null;
    if ((api.registrationMode ?? "full") === "full") {
      backendService = createBackendService(api, {
        onStatus: async (status) => record(api, {
          event_type: "backend_lifecycle_event",
          task_id: `agentmeter-backend-${Date.now()}`,
          action: status.status,
          evidence: status.message ?? "AgentMeter-Gov backend lifecycle changed.",
          backend: status,
        }),
      });
      // The gateway does not report "ready" until every registered service's
      // start() resolves, and a cold boot can take far longer than a warm
      // restart to bring the packaged backend up. Waiting inline therefore left
      // the OpenClaw control UI unreachable after sign-in until the gateway was
      // restarted. Confirm readiness in the background instead; every tool
      // decision still calls ensureReady() first, and failClosed keeps calls
      // safe while the backend is starting.
      api.registerService({
        ...backendService,
        start: (ctx, options = {}) => backendService.start(ctx, { awaitReady: false, ...options }),
      });
    }

    let heartbeatContinuationHookRegistered = false;
    try {
      api.on(
        "heartbeat_prompt_contribution",
        async (event, ctx) => {
          const sessionKey = String(event?.sessionKey ?? ctx?.sessionKey ?? "");
          const approval = await findApprovedContinuationForSession(api, sessionKey);
          const prependContext = approvalContinuationContext(approval);
          if (!prependContext) return undefined;
          await record(api, {
            event_type: "approval_continuation_event",
            task_id: `openclaw-approval-continuation-${String(approval.reviewId ?? Date.now())}`,
            session_key: sessionKey,
            approval_id: approval.approvalId ?? "",
            review_id: approval.reviewId ?? "",
            action: "inject_approved_goal_into_heartbeat",
            evidence: "A valid unconsumed approval was matched to the originating session for controlled continuation.",
          });
          return { prependContext };
        },
        { priority: 1000, timeoutMs: 5000 },
      );
      heartbeatContinuationHookRegistered = true;
    } catch (error) {
      api.logger?.warn?.(`AgentMeter-Gov automatic approval continuation is unavailable: ${String(error?.message ?? error)}`);
    }

    api.on(
      "before_agent_run",
      async (event, ctx) => {
        const key = contextKey(event, ctx);
        const prompt = String(event?.prompt ?? "");
        const sessionKey = String(ctx?.sessionKey ?? event?.sessionKey ?? "");
        const approvedHeartbeatContinuation = isHeartbeatRun(prompt, ctx, event)
          ? await findApprovedContinuationForSession(api, sessionKey)
          : null;
        const effectiveUserGoal = approvedHeartbeatContinuation?.originalUserGoal ?? prompt;
        const inherited = inheritedContextBySession.get(sessionKey) ?? null;
        const taskId = `openclaw-live-${String(ctx?.runId ?? event?.runId ?? Date.now())}`;
        const state = {
          taskId,
          auditId: taskId,
          sessionKey,
          userGoal: effectiveUserGoal,
          historyEvents: [],
          proposedSideEffects: [],
          hiddenInstructionDetected: false,
          guardBypassAttempt: isGuardBypassPrompt(prompt),
          inputRisk: assessInputRisk(prompt),
          maxRiskScore: Number(inherited?.maxRiskScore ?? 0),
          blocked: Boolean(inherited?.blocked),
          tainted: Boolean(inherited?.tainted),
          authorization: inherited?.authorization ?? inferAuthorization(effectiveUserGoal),
          dataLevel: inherited?.dataLevel ?? inferPromptDataLevel(effectiveUserGoal),
          parentAuditId: inherited?.parentAuditId ?? "",
          approvalCommand: null,
          approvalContext: approvedHeartbeatContinuation ? {
            reviewId: approvedHeartbeatContinuation.reviewId,
            scope: approvedHeartbeatContinuation.scope,
            originalUserGoal: approvedHeartbeatContinuation.originalUserGoal,
          } : null,
          supplyChainScanCommand: null,
          operationBudget: { total: 0, search: 0, fingerprints: new Map() },
          inputSources: [
            {
              name: approvedHeartbeatContinuation ? "Approved pending-review context" : "OpenClaw user prompt",
              type: approvedHeartbeatContinuation ? "human_approval" : "user",
              trust: "high",
              tags: approvedHeartbeatContinuation ? ["approval", "original_user_goal"] : ["user_goal"],
              content: effectiveUserGoal.slice(0, 1200),
            },
            ...(inherited ? [{
              name: "Inherited parent-agent context",
              type: "subagent_inheritance",
              trust: inherited.tainted ? "low" : "medium",
              tags: ["parent_risk", "authorization_scope", "data_level"],
              content: `parent_audit_id=${inherited.parentAuditId}; risk=${inherited.maxRiskScore}; data_level=${inherited.dataLevel}`,
            }] : []),
          ],
        };
        sessionState.set(key, state);
        if (state.blocked || state.tainted) {
          state.maxRiskScore = Math.max(state.maxRiskScore, 96);
          await record(api, {
            event_type: "subagent_event",
            task_id: state.taskId,
            audit_id: state.auditId,
            parent_audit_id: state.parentAuditId,
            session_key: sessionKey,
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            action: "block_inherited_context",
            risk_score: state.maxRiskScore,
            inherited_authorization: state.authorization,
            inherited_data_level: state.dataLevel,
            tainted: state.tainted,
            evidence: "Child agent inherited a blocked or tainted parent context.",
          });
          return {
            outcome: "block",
            reason: "inherited_parent_risk",
            message: "AgentMeter-Gov blocked a child task inherited from a blocked or tainted parent.",
            category: "subagent_inherited_risk",
          };
        }
        const approvalCommand = parseApprovalCommand(prompt);
        if (approvalCommand) {
          state.approvalCommand = approvalCommand;
          const approvalState = await reviewPendingReview(api, approvalCommand, prompt, ctx, event);
          let continuation = { requested: false, queued: false, reason: "not_approved" };
          if (approvalState.decision === "approve" && approvalState.originalUserGoal) {
            state.approvalContext = {
              reviewId: approvalState.reviewId,
              scope: approvalState.scope,
              originalUserGoal: approvalState.originalUserGoal,
            };
            state.userGoal = approvalState.originalUserGoal;
            continuation = await requestApprovedContinuation(api, approvalState, {
              sessionKey: approvalState.releaseSessionKey || sessionKey,
              agentId: ctx?.agentId,
              approvalStoreFallback: heartbeatContinuationHookRegistered,
            });
            state.inputSources.push({
              name: "Approved pending-review context",
              type: "human_approval",
              trust: "high",
              tags: ["approval", "original_user_goal"],
              content: `review_id=${approvalState.reviewId}; original_goal=${approvalState.originalUserGoal.slice(0, 800)}`,
            });
          }
          await record(api, {
            event_type: "approval_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            approval_id: approvalState.approvalId,
            review_id: approvalState.reviewId,
            review_decision: approvalState.decision,
            approval_scope: approvalState.scope,
            approval_origin_session_key: approvalState.originSessionKey ?? "",
            approval_session_key: String(ctx?.sessionKey ?? ""),
            approval_release_session_key: approvalState.releaseSessionKey ?? "",
            cross_session_approval: Boolean(approvalState.crossSession),
            approver_user_id: String(ctx?.userId ?? ctx?.accountId ?? "openclaw_user"),
            continuation_requested: continuation.requested,
            continuation_queued: continuation.queued,
            continuation_reason: continuation.reason,
            evidence: approvalState.message,
          });
          state.approvalCommand = null;
          const message = approvalState.decision === "approve" && approvalState.originalUserGoal
            ? continuation.requested
              ? `${approvalState.message} 已进入续执行队列，无需再次发送原请求。`
              : continuation.queued
                ? `${approvalState.message} 原操作已排队，但即时唤醒不可用；OpenClaw 下次活动时会继续。`
                : `${approvalState.message} 自动续执行不可用，请重新发送一次原请求；审批凭证仍在有效期内。`
            : approvalState.message;
          return {
            outcome: "block",
            reason: approvalState.decision === "reject"
              ? "human_review_rejected"
              : "human_review_controlled_continuation",
            message,
            category: "human_review_workflow",
            metadata: {
              approval_id: approvalState.approvalId,
              review_id: approvalState.reviewId,
              continuation_requested: continuation.requested,
            },
          };
        }
        const scanCommand = parseSupplyChainScanCommand(prompt);
        if (scanCommand) {
          const resolvedScanCommand = resolveSupplyChainPaths(
            scanCommand,
            String(ctx?.workspaceDir ?? ctx?.cwd ?? process.cwd()),
          );
          state.supplyChainScanCommand = resolvedScanCommand;
          const scanResult = await callSupplyChainScan(api, {
            task_id: state.taskId,
            baseline: resolvedScanCommand.baseline,
            candidate: resolvedScanCommand.candidate,
          }, backendService).catch((error) => ({
            error: String(error?.message ?? error),
            risk_measurement: {
              action: "block",
              total_score: 100,
              matched_rules: ["SUPPLY-CHAIN-SCAN-FAIL-CLOSED: scanner unavailable, block component enablement"],
            },
          }));
          await record(api, {
            event_type: "supply_chain_scan_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            baseline: resolvedScanCommand.baseline,
            candidate: resolvedScanCommand.candidate,
            scanner: scanResult.scan?.scanner ?? "",
            action: scanResult.risk_measurement?.action ?? "unknown",
            risk_score: scanResult.risk_measurement?.total_score ?? scanResult.scan?.risk_score ?? 0,
            triggered_rules: scanResult.risk_measurement?.matched_rules ?? [],
            audit_report_path: scanResult.audit_report_path ?? "",
            error: scanResult.error ?? "",
            evidence: "OpenClaw requested AgentMeter-Gov Skill/plugin supply-chain scan before enabling a component.",
          });
        }
        await record(api, {
          event_type: "input_event",
          task_id: state.taskId,
          session_key: String(ctx?.sessionKey ?? ""),
          run_id: String(ctx?.runId ?? event?.runId ?? ""),
          user_goal: state.userGoal,
          trigger_prompt: state.userGoal === prompt ? "" : prompt,
          explicit_authorization: inferAuthorization(state.userGoal),
          content_source: approvedHeartbeatContinuation ? "approved continuation" : "OpenClaw prompt",
          source_trust: "high",
          evidence: "OpenClaw before_agent_run captured the original user goal",
        });
        if (state.guardBypassAttempt) {
          updateRiskState(state, 100, "secret", true, true);
          await record(api, {
            event_type: "risk_decision_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: "before_agent_run",
            proposed_tool_call: {
              name: "run_shell",
              params: { command: prompt.slice(0, 500) },
              source: "openclaw_before_agent_run",
              data_level: "internal",
              result: "preparing",
              evidence: "Prompt attempts to disable or bypass AgentMeter-Gov protection.",
            },
            gate_action: "block",
            allowed: false,
            risk_score: 100,
            triggered_rules: ["GUARD-BYPASS: attempt to disable or bypass AgentMeter-Gov protection"],
            decision: "block",
            evidence: "AgentMeter-Gov runs in mandatory enforce mode and blocks attempts to turn off or bypass the guard.",
          });
          return {
            outcome: "block",
            reason: "guard_bypass_attempt",
            message: "AgentMeter-Gov 处于强制防护模式，已阻断关闭、绕过或禁用防护的输入。",
            category: "security_policy_bypass",
          };
        }
        if (state.inputRisk) {
          updateRiskState(state, state.inputRisk.score, state.dataLevel, true, true);
          await record(api, inputRiskDecisionEvent(state, state.inputRisk, prompt, event, ctx));
          return {
            outcome: "block",
            reason: state.inputRisk.reason,
            message: state.inputRisk.message,
            category: state.inputRisk.category,
            metadata: { risk_score: state.inputRisk.score, triggered_rules: state.inputRisk.rules },
          };
        }
      },
      { priority: 100, timeoutMs: 5000 },
    );

    api.on(
      "before_tool_call",
      async (event, ctx) => {
        const key = contextKey(event, ctx);
        const state = ensureState(key, event, ctx);
        const budgetStop = consumeOperationBudget(state, event, api.pluginConfig ?? {});
        if (budgetStop) {
          await record(api, {
            event_type: "performance_budget_event",
            task_id: state.taskId,
            audit_id: state.auditId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: String(event?.toolName ?? ""),
            action: "stop_excessive_tool_loop",
            budget_reason: budgetStop.reason,
            budget_counts: budgetStop.counts,
            budget_limits: budgetStop.limits,
            evidence: "Per-turn tool/search/retry budget exhausted before another tool call.",
          });
          return { block: true, blockReason: budgetStop.message };
        }
        const inspectedEvent = await attachExistingWriteContent(event, ctx);
        const proposed = mapToolEvent(inspectedEvent, "preparing", state.userGoal);
        const proposedForGate = await withSideEffectBurstMarker(api, state, proposed, ctx, event);
        const boundary = classifyOperationBoundary({
          event,
          ctx,
          proposed: proposedForGate,
          taskRiskLocked: Boolean(state.blocked || state.tainted || state.guardBypassAttempt),
        });
        const governanceKey = toolEventKey(event, ctx);
        toolGovernanceContext.set(governanceKey, {
          ...(toolGovernanceContext.get(governanceKey) ?? {}),
          boundary,
          taskId: state.taskId,
          sessionKey: String(ctx?.sessionKey ?? ""),
          runId: String(ctx?.runId ?? event?.runId ?? ""),
        });
        const memoryGovernance = assessMemoryOperation(
          { ...proposedForGate, params: event?.params ?? proposedForGate.params },
          state.userGoal,
        );
        if (memoryGovernance) {
          toolGovernanceContext.set(governanceKey, {
            ...(toolGovernanceContext.get(governanceKey) ?? {}),
            memory: memoryGovernance,
            taskId: state.taskId,
            sessionKey: String(ctx?.sessionKey ?? ""),
            runId: String(ctx?.runId ?? event?.runId ?? ""),
          });
          const blockedMemory = await enforceMemoryBeforeTool(api, memoryGovernance, state, ctx, event, proposedForGate);
          if (blockedMemory) return blockedMemory;
          if (memoryGovernance.localAllow === true) {
            updateRiskState(state, Number(memoryGovernance.score ?? 12), proposedForGate.data_level);
            await record(api, {
              event_type: "risk_decision_event",
              task_id: state.taskId,
              session_key: String(ctx?.sessionKey ?? ""),
              run_id: String(ctx?.runId ?? event?.runId ?? ""),
              tool_name: String(event?.toolName ?? ""),
              proposed_tool_call: proposedForGate,
              gate_action: "allow",
              allowed: true,
              gate_latency_ms: 0,
              risk_score: Number(memoryGovernance.score ?? 12),
              triggered_rules: memoryGovernance.rules ?? ["MEM-WRITE-ALLOW: benign preference or work memory"],
              decision: "allow",
              ...boundaryAuditFields(boundary),
              evidence: "A plain preference memory write is locally allowed; lineage and output governance remain active.",
            });
            return undefined;
          }
        }
        if (proposedForGate.params?.agentmeter_edit_semantics?.benign_scoped_cleanup === true) {
          updateRiskState(state, 18, proposedForGate.data_level);
          await record(api, {
            event_type: "risk_decision_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: String(event?.toolName ?? ""),
            proposed_tool_call: proposedForGate,
            gate_action: "allow",
            allowed: true,
            gate_latency_ms: 0,
            risk_score: 18,
            triggered_rules: ["CLEANUP-LOCAL-ALLOW: exact disposable temp/log file explicitly authorized"],
            decision: "allow",
            ...boundaryAuditFields(boundary),
            evidence: "An exact, non-wildcard temporary-file cleanup was explicitly requested; full audit remains active.",
          });
          return undefined;
        }
        if (state.guardBypassAttempt) {
          await record(api, {
            event_type: "risk_decision_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: String(event?.toolName ?? ""),
            proposed_tool_call: proposedForGate,
            gate_action: "block",
            allowed: false,
            risk_score: 100,
            triggered_rules: ["GUARD-BYPASS: attempt to disable or bypass AgentMeter-Gov protection"],
            decision: "block",
            evidence: "Tool call blocked because this turn attempted to disable or bypass AgentMeter-Gov.",
          });
          return {
            block: true,
            blockReason: "AgentMeter-Gov 处于正式强制防护模式，已阻断关闭、绕过或禁用防护的尝试。",
          };
        }
        if (state.supplyChainScanCommand) {
          await record(api, {
            event_type: "risk_decision_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: String(event?.toolName ?? ""),
            proposed_tool_call: proposedForGate,
            gate_action: "supply_chain_scan_handled",
            allowed: false,
            risk_score: 0,
            triggered_rules: ["SUPPLY-CHAIN-SCAN-HANDLED: scan command handled by AgentMeter-Gov Guard"],
            decision: "supply_chain_scan_handled",
            evidence: "This turn requested a Skill/plugin scan; extra tool calls are ignored after scan completion.",
          });
          return {
            block: true,
            blockReason: "AgentMeter-Gov supply-chain scan has been completed for this turn; no extra tool call is required.",
          };
        }
        const componentLifecycle = componentLifecycleRequest(event?.toolName, event?.params);
        if (componentLifecycle) {
          const scanResult = componentLifecycle.candidate
            ? await callSupplyChainScan(api, {
                task_id: state.taskId,
                baseline: componentLifecycle.baseline,
                candidate: componentLifecycle.candidate,
              }, backendService).catch((error) => ({ error: String(error?.message ?? error) }))
            : { error: "component path is required for supply-chain verification" };
          const lifecycleDecision = classifySupplyChainResult(scanResult, componentLifecycle);
          await record(api, {
            event_type: "supply_chain_scan_event",
            task_id: state.taskId,
            audit_id: state.auditId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: String(event?.toolName ?? ""),
            baseline: componentLifecycle.baseline,
            candidate: componentLifecycle.candidate,
            action: lifecycleDecision.action,
            risk_score: scanResult.risk_measurement?.total_score ?? scanResult.scan?.risk_score ?? 100,
            signature_status: scanResult.scan?.signature_verification?.status ?? "unverified",
            version_lock_status: scanResult.scan?.version_lock_verification?.status ?? "unverified",
            declared_capabilities: scanResult.scan?.declared_capabilities ?? [],
            observed_capabilities: scanResult.scan?.observed_capabilities ?? [],
            capability_comparison: scanResult.scan?.capability_comparison ?? {},
            sbom: scanResult.scan?.sbom ?? {},
            evidence: `Component lifecycle verification: ${lifecycleDecision.reason}.`,
            error: scanResult.error ?? "",
          });
          if (!lifecycleDecision.allowed) {
            return {
              block: true,
              blockReason: lifecycleDecision.action === "human_review"
                ? "AgentMeter-Gov requires a signed, version-locked component or explicit supply-chain review before enablement."
                : "AgentMeter-Gov blocked component enablement because supply-chain verification failed.",
            };
          }
        }
        if (String(event?.toolName ?? "") === "sessions_spawn") {
          const subagentBlock = await governSubagentToolCall(api, state, event, ctx);
          if (subagentBlock) return subagentBlock;
        }
        if (boundary.local_allow) {
          await record(api, {
            event_type: "risk_decision_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: String(event?.toolName ?? ""),
            proposed_tool_call: proposedForGate,
            gate_action: "allow",
            allowed: true,
            gate_latency_ms: 0,
            risk_score: 6,
            triggered_rules: ["COMPAT-LOCAL-ALLOW: verified read-only OpenClaw/plugin operation"],
            decision: "allow",
            ...boundaryAuditFields(boundary),
            evidence: `${boundary.reason} Full audit and output governance remain active.`,
          });
          return undefined;
        }
        const payload = {
          schema_version: "agentmeter.event.v1",
          adapter: "openclaw",
          event_type: "tool_proposal",
          timestamp: new Date().toISOString(),
          protocol_stage: "before_tool_call",
          task_id: state.taskId,
          audit_id: state.auditId,
          parent_audit_id: state.parentAuditId,
          title: "OpenClaw before_tool_call live risk gate",
          user_id: String(ctx?.userId ?? ctx?.accountId ?? "openclaw_user"),
          session_key: String(ctx?.sessionKey ?? ""),
          run_id: String(ctx?.runId ?? event?.runId ?? ""),
          task: {
            id: state.taskId,
            title: "OpenClaw before_tool_call live risk gate",
            user_id: String(ctx?.userId ?? ctx?.accountId ?? "openclaw_user"),
            goal: state.userGoal,
          },
          context: {
            session_key: String(ctx?.sessionKey ?? ""),
            input_sources: state.inputSources,
            approval_context: state.approvalContext,
            operation_boundary: boundaryAuditFields(boundary),
          },
          history: state.historyEvents,
          operation: proposedForGate,
        };
        const gateStartedAt = performance.now();
        let result = await callGate(api, payload, backendService);
        const gateLatencyMs = Math.round((performance.now() - gateStartedAt) * 10) / 10;
        if (memoryGovernance?.action === "human_review" && result.gate_action !== "block") {
          result = {
            ...result,
            gate_action: "human_review",
            allowed: false,
            message: memoryGovernance.evidence,
            risk_measurement: {
              ...(result.risk_measurement ?? {}),
              total_score: Math.max(Number(result.risk_measurement?.total_score ?? 0), memoryGovernance.score),
              matched_rules: [
                ...new Set([...(result.risk_measurement?.matched_rules ?? []), ...memoryGovernance.rules]),
              ],
            },
          };
        }
        const existingPending =
          result.gate_action !== "block" && result.gate_action !== "human_review"
            ? await findOpenPendingReviewForProposed(api, proposedForGate, ctx, event)
            : null;
        if (existingPending) {
          result = {
            ...result,
            gate_action: "human_review",
            allowed: false,
            message: `Existing pending review ${existingPending.reviewId} still locks this action; approve that review before retrying.`,
            risk_measurement: {
              ...(result.risk_measurement ?? {}),
              total_score: Math.max(result.risk_measurement?.total_score ?? 0, existingPending.riskScore ?? 45),
              matched_rules: existingPending.matchedRules ?? result.risk_measurement?.matched_rules ?? [],
            },
          };
        }
        const approvedReview =
          result.gate_action === "human_review"
            ? await consumeApproval(api, proposedForGate, result, state, ctx, event)
            : null;
        if (result.gate_action === "human_review" && !approvedReview) {
          const pending = await createPendingReview(api, proposedForGate, result, state, ctx, event);
          result.message = formatHumanReviewMessage(proposedForGate, result, pending);
        }
        const effectiveGateAction = approvedReview ? "human_review_approved" : result.gate_action;
        const effectiveAllowed = approvedReview ? true : result.allowed;
        updateRiskState(
          state,
          Number(result.risk_measurement?.total_score ?? 0),
          proposedForGate.data_level,
          effectiveGateAction === "block",
          state.tainted,
        );
        if (String(event?.toolName ?? "") === "sessions_spawn") {
          const pending = [...pendingSubagentInheritances]
            .reverse()
            .find((item) => item.parentSessionKey === String(ctx?.sessionKey ?? state.sessionKey ?? ""));
          if (pending) pending.inherited = evaluateSubagentInheritance(state).inherited;
        }
        if (memoryGovernance) {
          await record(api, memoryGovernanceEvent(memoryGovernance, state, ctx, event, {
            action: effectiveGateAction,
            allowed: effectiveAllowed,
            approvalId: approvedReview?.approvalId ?? "",
            reviewId: approvedReview?.reviewId ?? "",
          }));
        }
        await record(api, {
          event_type: "risk_decision_event",
          task_id: state.taskId,
          session_key: String(ctx?.sessionKey ?? ""),
          run_id: String(ctx?.runId ?? event?.runId ?? ""),
          tool_name: String(event?.toolName ?? ""),
          proposed_tool_call: proposedForGate,
          gate_action: effectiveGateAction,
          allowed: effectiveAllowed,
          gate_latency_ms: gateLatencyMs,
          gate_transport: result.gate_transport ?? {},
          gate_timings_ms: result.gate_timings_ms ?? {},
          risk_score: result.risk_measurement?.total_score,
          triggered_rules: result.risk_measurement?.matched_rules ?? [],
          security_control: result.security_control ?? result.risk_measurement?.control_plan ?? {},
          scoring_details: result.risk_measurement?.scoring_details ?? {},
          factor_contributions: result.risk_measurement?.scoring_details?.factor_contributions ?? {},
          threshold_explanation: result.risk_measurement?.scoring_details?.threshold_explanation ?? {},
          recovery_plan:
            result.security_control?.recovery_plan ?? result.risk_measurement?.scoring_details?.recovery_plan ?? {},
          recovery_execution:
            result.security_control?.recovery_execution ?? result.risk_measurement?.scoring_details?.recovery_execution ?? {},
          execution_graph: result.audit_report?.execution_graph ?? {},
          audit_completeness: result.audit_report?.audit_completeness ?? {},
          report_hash: result.audit_report?.report_hash ?? "",
          approval_id: approvedReview?.approvalId ?? "",
          review_id: approvedReview?.reviewId ?? "",
          decision: effectiveGateAction,
          ...boundaryAuditFields(boundary),
          evidence: approvedReview?.message ?? result.message,
        });
        if (approvedReview) {
          return undefined;
        }
        if (result.gate_action === "block" || result.gate_action === "human_review") {
          const stopRetryMessage = result.gate_action === "human_review"
            ? "AgentMeter-Gov 已暂停当前动作并等待人工确认。本轮不要改用 exec、PowerShell、回收站 API 或其他工具重试同一副作用；请直接向用户报告审批 ID 并停止。"
            : "AgentMeter-Gov 已阻断当前动作。本轮不要改用其他工具、命令或编码方式绕过；请直接报告阻断结果并停止。";
          return {
            block: true,
            blockReason: `${result.message || "AgentMeter-Gov blocked risky tool call"}\n${stopRetryMessage}`,
          };
        }
        return undefined;
      },
      { priority: 1000, timeoutMs: 60000 },
    );

    api.on(
      "after_tool_call",
      async (event, ctx) => {
        const key = contextKey(event, ctx);
        const state = ensureState(key, event, ctx);
        const observed = mapToolEvent(event, "executed", state.userGoal);
        const toolOutput = extractToolOutput(event);
        observed.result = toolExecutionOutcome(event, isBlockedToolResult(event, toolOutput));
        state.historyEvents.push(observed);
        const governanceContext = toolGovernanceContext.get(toolEventKey(event, ctx));
        if (governanceContext?.memory?.operation === "write" && observed.result === "success") {
          const lineage = await recordMemoryLineage(memoryGovernanceStatePath(api), {
            path: governanceContext.memory.path,
            content_hash: governanceContext.memory.contentHash ?? "",
            classification: governanceContext.memory.classification,
            tainted: false,
            source_session: String(ctx?.sessionKey ?? ""),
            source_run: String(ctx?.runId ?? event?.runId ?? ""),
            approval_required: governanceContext.memory.action === "human_review",
          });
          await record(api, {
            event_type: "memory_governance_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            memory_path: governanceContext.memory.path,
            memory_operation: "write_committed",
            memory_classification: governanceContext.memory.classification,
            lineage_id: lineage.lineage_id,
            tainted: false,
            action: "persisted",
            evidence: "Approved memory content was persisted with lineage metadata.",
          });
        }
        const hiddenInspectionObserved = governanceContext?.boundary?.operation_class === "extension_read_only"
          ? { ...observed, name: "read_document" }
          : observed;
        const hidden = detectHiddenInstruction({ ...hiddenInspectionObserved, user_goal: state.userGoal }, toolOutput);
        if (hidden && !state.hiddenInstructionDetected) {
          state.hiddenInstructionDetected = true;
          updateRiskState(state, 88, observed.data_level, true, true);
          const hiddenSource = {
            name: "Hidden or low-trust instruction in document",
            type: "document_embedded_instruction",
            trust: "low",
            tags: ["prompt_injection", ...hidden.indicators],
            content: hidden.preview,
          };
          state.inputSources.push(hiddenSource);
          const injectionEvent = {
            name: "prompt_injection_detected",
            params: {
              source_file: observed.params.path ?? observed.params.file ?? "",
              indicators: hidden.indicators,
            },
            source: "openclaw_after_tool_call",
            data_level: "public",
            result: "detected",
            evidence: "Read content contains instructions to access internal data, write an outbox file, send externally, or hide the behavior.",
          };
          state.historyEvents.push(injectionEvent);
          await record(api, {
            event_type: "input_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            user_goal: state.userGoal,
            content_source: "document_embedded_instruction",
            source_trust: "low",
            indicators: hidden.indicators,
            evidence: hidden.preview,
          });
          await record(api, {
            event_type: "risk_decision_event",
            task_id: state.taskId,
            session_key: String(ctx?.sessionKey ?? ""),
            run_id: String(ctx?.runId ?? event?.runId ?? ""),
            tool_name: observed.name,
            proposed_tool_call: {
              name: "prompt_injection_detected",
              params: {
                source_file: observed.params.path ?? observed.params.file ?? "",
                indicators: hidden.indicators,
              },
              source: "openclaw_after_tool_call",
              data_level: "public",
              result: "detected",
              evidence: hidden.preview.slice(0, 500),
            },
            gate_action: "block",
            allowed: false,
            risk_score: 88,
            triggered_rules: ["PROMPT-INJECTION: low-trust document contains hidden tool-use instructions"],
            decision: "block",
            evidence: "Hidden instruction detected after document read; continuation of the risky chain is blocked/audited.",
          });
        }
        await record(api, {
          event_type: "tool_event",
          task_id: state.taskId,
          session_key: String(ctx?.sessionKey ?? ""),
          run_id: String(ctx?.runId ?? event?.runId ?? ""),
          tool_name: observed.name,
          action: observed.name,
          parameters: observed.params,
          data_object: observed.params.path ?? observed.params.file ?? "",
          sensitivity: observed.data_level,
          target: observed.params.to ?? observed.params.url ?? observed.params.path ?? "",
          side_effect: isSideEffect(observed),
          ...boundaryAuditFields(governanceContext?.boundary),
          status: observed.result,
          evidence: observed.evidence,
        });
      },
      { priority: 100, timeoutMs: 5000 },
    );

    api.on(
      "tool_result_persist",
      (event, ctx) => {
        let message = event?.message;
        let changed = false;
        const governanceContext = toolGovernanceContext.get(toolEventKey(event, ctx));
        if (governanceContext?.memory?.operation === "read") {
          const sanitized = sanitizeMemoryMessage(message);
          if (sanitized.changed) {
            changed = true;
            message = sanitized.message;
            scheduleBackground(api, "memory read sanitization audit", async () => {
              const lineage = await recordMemoryLineage(memoryGovernanceStatePath(api), {
                path: governanceContext.memory.path,
                content_hash: createHash("sha256").update(String(sanitized.removed.join("\n"))).digest("hex"),
                classification: "malicious_persistent_instruction",
                tainted: true,
                source_session: String(ctx?.sessionKey ?? ""),
                source_run: String(ctx?.runId ?? event?.runId ?? ""),
              });
              const cleanup = await cleanMemoryTarget(api, governanceContext.memory.path, ctx);
              await record(api, {
                event_type: "memory_governance_event",
                task_id: governanceContext.taskId,
                session_key: String(ctx?.sessionKey ?? governanceContext.sessionKey ?? ""),
                run_id: String(ctx?.runId ?? event?.runId ?? governanceContext.runId ?? ""),
                memory_path: governanceContext.memory.path,
                memory_operation: "read_sanitized",
                memory_classification: "malicious_persistent_instruction",
                lineage_id: lineage.lineage_id,
                tainted: true,
                action: "block_and_clean",
                cleanup_status: cleanup.reason,
                quarantine_path: cleanup.backupPath ?? "",
                evidence: "Poisoned persistent instructions were removed before the memory content reached the model.",
              });
            });
          }
        }
        const guarded = guardPersistedToolResult(message);
        if (guarded.action !== "allow") {
          changed = true;
          message = guarded.message;
          scheduleBackground(api, "tool result output audit", () => (
            recordOutputGuard(api, guarded, "tool_result", event, ctx)
          ));
        }
        return changed ? { message } : undefined;
      },
      { priority: 1000, timeoutMs: 5000 },
    );

    registerOutputGovernanceHooks(api, {
      recordOutputGuard: (result, surface, event, ctx) => (
        recordOutputGuard(api, result, surface, event, ctx)
      ),
      scheduleBackground,
    });

    api.on(
      "subagent_spawned",
      async (event, ctx) => {
        const childSessionKey = String(event?.childSessionKey ?? "");
        const requesterSessionKey = String(ctx?.requesterSessionKey ?? "");
        let pendingIndex = -1;
        for (let index = pendingSubagentInheritances.length - 1; index >= 0; index -= 1) {
          if (!requesterSessionKey || pendingSubagentInheritances[index].parentSessionKey === requesterSessionKey) {
            pendingIndex = index;
            break;
          }
        }
        const pending = pendingIndex >= 0 ? pendingSubagentInheritances.splice(pendingIndex, 1)[0] : null;
        const inherited = pending?.inherited ?? inheritedContextBySession.get(childSessionKey);
        if (childSessionKey && inherited) inheritedContextBySession.set(childSessionKey, inherited);
        await record(api, {
          event_type: "subagent_event",
          task_id: pending?.taskId ?? inherited?.parentAuditId ?? `openclaw-subagent-${Date.now()}`,
          parent_audit_id: inherited?.parentAuditId ?? "",
          parent_session_key: pending?.parentSessionKey ?? requesterSessionKey,
          child_session_key: childSessionKey,
          child_agent_id: String(event?.agentId ?? ""),
          action: "spawned",
          inherited_authorization: inherited?.authorization ?? [],
          inherited_data_level: inherited?.dataLevel ?? "public",
          risk_score: Number(inherited?.maxRiskScore ?? 0),
          evidence: "OpenClaw confirmed the governed child agent was spawned.",
        });
      },
      { priority: 100, timeoutMs: 5000 },
    );

    api.on(
      "subagent_ended",
      async (event, ctx) => {
        const childSessionKey = String(event?.targetSessionKey ?? event?.childSessionKey ?? ctx?.sessionKey ?? "");
        const inherited = inheritedContextBySession.get(childSessionKey);
        await record(api, {
          event_type: "subagent_event",
          task_id: inherited?.parentAuditId || `openclaw-subagent-${Date.now()}`,
          parent_audit_id: inherited?.parentAuditId ?? "",
          child_session_key: childSessionKey,
          child_agent_id: String(event?.agentId ?? ""),
          action: "ended",
          status: String(event?.status ?? event?.outcome ?? "completed"),
          evidence: "Governed child-agent lifecycle completed.",
        });
        inheritedContextBySession.delete(childSessionKey);
      },
      { priority: 100, timeoutMs: 5000 },
    );

    api.on(
      "agent_end",
      async (event, ctx) => {
        const key = contextKey(event, ctx);
        const state = sessionState.get(key);
        if (!state) {
          return;
        }
        const finalOutput = guardText(finalAssistantText(event), { surface: "output" });
        if (finalOutput.action !== "allow") {
          await recordOutputPostflight(api, finalOutput, event, ctx);
        }
        const outcome = agentExecutionOutcome(event);
        const executionError = guardText(outcome.execution_error, { surface: "output" }).text;
        await record(api, {
          event_type: "result_event",
          task_id: state.taskId,
          session_key: String(ctx?.sessionKey ?? ""),
          run_id: String(ctx?.runId ?? event?.runId ?? ""),
          ...outcome,
          execution_error: executionError,
          actual_effect: summarizeEffects(state.historyEvents),
          blocked_effect: summarizeBlockedEffects(state.historyEvents),
          final_response: finalOutput.text,
          evidence: outcome.execution_result === "failed"
            ? `OpenClaw 执行失败：${executionError}。本轮结束不代表业务操作成功。`
            : "AgentMeter-Gov Guard observed agent_end; business completion requires a separate receipt.",
        });
        for (const [toolKey, value] of toolGovernanceContext) {
          if (value.taskId === state.taskId) toolGovernanceContext.delete(toolKey);
        }
        sessionState.delete(key);
      },
      { priority: 100, timeoutMs: 5000 },
    );
  },
});

function contextKey(event, ctx) {
  const runId = String(ctx?.runId ?? event?.runId ?? "").trim();
  if (runId) {
    return `run:${runId}`;
  }
  const sessionKey = String(ctx?.sessionKey ?? event?.sessionKey ?? "").trim();
  return sessionKey ? `session:${sessionKey}` : "default";
}

function ensureState(key, event, ctx) {
  let state = sessionState.get(key);
  if (!state) {
    state = {
      taskId: `openclaw-live-${String(ctx?.runId ?? event?.runId ?? Date.now())}`,
      auditId: `openclaw-live-${String(ctx?.runId ?? event?.runId ?? Date.now())}`,
      sessionKey: String(ctx?.sessionKey ?? event?.sessionKey ?? ""),
      userGoal: "",
      historyEvents: [],
      proposedSideEffects: [],
      hiddenInstructionDetected: false,
      guardBypassAttempt: false,
      maxRiskScore: 0,
      blocked: false,
      tainted: false,
      authorization: [],
      dataLevel: "public",
      parentAuditId: "",
      approvalCommand: null,
      approvalContext: null,
      supplyChainScanCommand: null,
      inputSources: [
        {
          name: "OpenClaw runtime",
          type: "openclaw_runtime",
          trust: "medium",
          tags: ["runtime"],
          content: "before_agent_run prompt unavailable; using tool-call-only gate.",
        },
      ],
    };
    sessionState.set(key, state);
  }
  return state;
}

async function enforceMemoryBeforeTool(api, memory, state, ctx, event, proposed) {
  if (memory.operation === "read") {
    const taint = await findActiveTaint(memoryGovernanceStatePath(api), memory.path);
    if (!taint) return null;
    const cleanup = await cleanMemoryTarget(api, memory.path, ctx);
    await record(api, memoryGovernanceEvent(memory, state, ctx, event, {
      action: "block_tainted_read",
      allowed: false,
      lineageId: taint.lineage_id,
      tainted: true,
      cleanupStatus: cleanup.reason,
      quarantinePath: cleanup.backupPath ?? "",
    }));
    await record(api, {
      event_type: "risk_decision_event",
      task_id: state.taskId,
      session_key: String(ctx?.sessionKey ?? ""),
      run_id: String(ctx?.runId ?? event?.runId ?? ""),
      tool_name: String(event?.toolName ?? ""),
      proposed_tool_call: proposed,
      gate_action: "block",
      allowed: false,
      risk_score: 96,
      triggered_rules: ["MEM-READ-TAINT: active cross-session memory contamination"],
      decision: "block",
      evidence: `Persistent memory is tainted by lineage ${taint.lineage_id}; read was blocked before model ingestion.`,
    });
    return { block: true, blockReason: "AgentMeter-Gov blocked tainted persistent memory and initiated cleanup." };
  }
  if (memory.action !== "block") return null;
  const lineage = await recordMemoryLineage(memoryGovernanceStatePath(api), {
    path: memory.path,
    content_hash: memory.contentHash ?? "",
    classification: memory.classification,
    tainted: true,
    active: false,
    source_session: String(ctx?.sessionKey ?? ""),
    source_run: String(ctx?.runId ?? event?.runId ?? ""),
    status: "blocked_before_persistence",
  });
  await record(api, memoryGovernanceEvent(memory, state, ctx, event, {
    action: "block",
    allowed: false,
    lineageId: lineage.lineage_id,
    tainted: true,
  }));
  await record(api, {
    event_type: "risk_decision_event",
    task_id: state.taskId,
    session_key: String(ctx?.sessionKey ?? ""),
    run_id: String(ctx?.runId ?? event?.runId ?? ""),
    tool_name: String(event?.toolName ?? ""),
    proposed_tool_call: proposed,
    gate_action: "block",
    allowed: false,
    risk_score: memory.score,
    triggered_rules: memory.rules,
    decision: "block",
    evidence: memory.evidence,
  });
  return { block: true, blockReason: "AgentMeter-Gov blocked a malicious persistent-memory write." };
}

function memoryGovernanceEvent(memory, state, ctx, event, decision = {}) {
  return {
    event_type: "memory_governance_event",
    task_id: state.taskId,
    session_key: String(ctx?.sessionKey ?? ""),
    run_id: String(ctx?.runId ?? event?.runId ?? ""),
    memory_path: memory.path,
    memory_operation: memory.operation,
    memory_classification: memory.classification,
    content_hash: memory.contentHash ?? "",
    risk_score: memory.score,
    triggered_rules: memory.rules,
    action: decision.action ?? memory.action,
    allowed: decision.allowed ?? memory.action === "allow",
    approval_id: decision.approvalId ?? "",
    review_id: decision.reviewId ?? "",
    lineage_id: decision.lineageId ?? "",
    tainted: decision.tainted ?? memory.action === "block",
    cleanup_status: decision.cleanupStatus ?? "",
    quarantine_path: decision.quarantinePath ?? "",
    evidence: memory.evidence ?? "Persistent memory operation evaluated before access.",
  };
}

async function recordOutputGuard(api, result, surface, event, ctx) {
  const state = sessionState.get(contextKey(event, ctx));
  await record(api, {
    event_type: "output_guard_event",
    task_id: state?.taskId ?? `openclaw-output-${String(ctx?.runId ?? event?.runId ?? Date.now())}`,
    session_key: String(ctx?.sessionKey ?? event?.sessionKey ?? ""),
    run_id: String(ctx?.runId ?? event?.runId ?? ""),
    surface,
    control_source: "agentmeter_output_gate",
    intervention_stage: surface,
    action: result.action,
    finding_count: result.findings?.length ?? 0,
    findings: [...new Set((result.findings ?? []).map((item) => item.id))],
    severities: [...new Set((result.findings ?? []).map((item) => item.severity))],
    blocked_media_count: result.blockedMedia?.length ?? 0,
    decision: result.action,
    evidence: `Sensitive content was ${result.action === "block" ? "blocked" : "redacted"} before leaving the protected runtime.`,
  });
}

async function recordOutputPostflight(api, result, event, ctx) {
  const state = sessionState.get(contextKey(event, ctx));
  await record(api, {
    event_type: "output_postflight_event",
    task_id: state?.taskId ?? `openclaw-output-${String(ctx?.runId ?? event?.runId ?? Date.now())}`,
    session_key: String(ctx?.sessionKey ?? event?.sessionKey ?? ""),
    run_id: String(ctx?.runId ?? event?.runId ?? ""),
    surface: "agent_end",
    control_source: "agentmeter_postflight_detector",
    intervention_stage: "after_agent_end",
    action: "detected_after_delivery",
    would_action: result.action,
    finding_count: result.findings?.length ?? 0,
    findings: [...new Set((result.findings ?? []).map((item) => item.id))],
    severities: [...new Set((result.findings ?? []).map((item) => item.severity))],
    decision: "postflight_detection",
    evidence: "Sensitive content remained in the final assistant message after active output hooks; this is a failure signal, not a successful intervention.",
  });
}

function scheduleBackground(api, label, work) {
  void Promise.resolve()
    .then(work)
    .catch((error) => {
      api.logger?.error?.(`[AgentMeter-Gov] ${label} failed: ${String(error?.message ?? error)}`);
    });
}

function memoryGovernanceStatePath(api) {
  const config = api.pluginConfig ?? {};
  return resolveRuntimePath(api, config.memoryGovernancePath ?? DEFAULT_MEMORY_STATE_FILE);
}

function memoryQuarantinePath(api) {
  const config = api.pluginConfig ?? {};
  return resolveRuntimePath(api, config.memoryQuarantinePath ?? DEFAULT_MEMORY_QUARANTINE_DIR);
}

async function cleanMemoryTarget(api, targetPath, ctx) {
  const raw = String(targetPath ?? "");
  const workspaceDir = String(ctx?.workspaceDir ?? ctx?.cwd ?? "");
  const absolute = isAbsolute(raw) ? raw : workspaceDir ? resolve(join(workspaceDir, raw)) : "";
  if (!absolute) return { changed: false, reason: "relative_path_without_workspace" };
  try {
    return await cleanPoisonedMemoryFile(absolute, memoryQuarantinePath(api));
  } catch (error) {
    return { changed: false, reason: `cleanup_failed:${String(error?.code ?? error?.message ?? error)}` };
  }
}

function toolEventKey(event, ctx) {
  const callId = String(event?.toolCallId ?? event?.callId ?? "").trim();
  if (callId) return `call:${callId}`;
  return `${contextKey(event, ctx)}|${String(event?.toolName ?? "unknown")}`;
}

function findStateBySession(sessionKey) {
  const expected = String(sessionKey ?? "");
  for (const state of sessionState.values()) {
    if (state.sessionKey === expected) return state;
  }
  return null;
}

async function governSubagentToolCall(api, state, event, ctx) {
  const decision = evaluateSubagentInheritance(state);
  const inherited = decision.inherited;
  const parentSessionKey = String(ctx?.sessionKey ?? event?.sessionKey ?? state.sessionKey ?? "");
  await record(api, {
    event_type: "subagent_event",
    task_id: state.taskId,
    audit_id: state.auditId,
    parent_audit_id: inherited.parentAuditId,
    parent_session_key: parentSessionKey,
    child_session_key: "pending",
    child_agent_id: String(event?.params?.agentId ?? event?.params?.agent ?? ""),
    label: String(event?.params?.label ?? ""),
    mode: String(event?.params?.mode ?? ""),
    action: decision.allowed ? "inherit_pending_spawn" : "block_spawn",
    risk_score: inherited.maxRiskScore,
    inherited_authorization: inherited.authorization,
    inherited_data_level: inherited.dataLevel,
    tainted: inherited.tainted,
    evidence: decision.allowed
      ? "Subagent tool call captured parent authorization, data level, risk and audit lineage before spawn."
      : "Subagent tool call blocked because delegation cannot downgrade blocked or tainted parent risk.",
  });
  if (!decision.allowed) {
    return { block: true, blockReason: "AgentMeter-Gov blocked subagent spawn due to inherited parent risk." };
  }
  pendingSubagentInheritances.push({
    parentSessionKey,
    taskId: state.taskId,
    inherited,
    createdAt: Date.now(),
  });
  while (pendingSubagentInheritances.length > 50) pendingSubagentInheritances.shift();
  return null;
}

function updateRiskState(state, score, dataLevel, blocked = false, tainted = false) {
  state.maxRiskScore = Math.max(Number(state.maxRiskScore ?? 0), Number(score ?? 0));
  state.dataLevel = maxDataLevel(state.dataLevel, dataLevel);
  state.blocked = Boolean(state.blocked || blocked);
  state.tainted = Boolean(state.tainted || tainted);
}

function inferPromptDataLevel(prompt) {
  const text = String(prompt ?? "");
  if (/\.env|private key|api[_ -]?key|password|token|\u5bc6\u7801|\u5bc6\u94a5/i.test(text)) return "secret";
  if (/staff|identity|phone|internal|\u8eab\u4efd\u8bc1|\u624b\u673a\u53f7|\u5185\u90e8/i.test(text)) return "internal_sensitive";
  return "public";
}

function maxDataLevel(left, right) {
  const ranks = { public: 0, internal: 1, internal_sensitive: 2, secret: 3 };
  const a = String(left ?? "public");
  const b = String(right ?? "public");
  return (ranks[b] ?? 0) > (ranks[a] ?? 0) ? b : a;
}

function mapToolEvent(event, result, userGoal = "") {
  const rawName = String(event?.toolName ?? "");
  let params = redact(event?.params ?? {});
  const text = JSON.stringify(params).toLowerCase();
  let name = canonicalRuntimeToolName(rawName, params);
  if (rawName === "read") {
    if (isSecretText(text)) {
      name = "read_secret";
    } else {
      name = /staff_sensitive|internal|staff|contact|roster|id_card|identity|phone|mobile|pii|user\.md|database_config|c:\\\\windows|\/etc\/passwd/.test(text) ? "read_sensitive_file" : "read_document";
    }
  } else if (rawName === "write" || rawName === "edit") {
    let editSemantics;
    if (rawName === "edit") {
      editSemantics = analyzeEditSemantics(params, userGoal);
      params = {
        ...params,
        agentmeter_raw_tool_name: "edit",
        agentmeter_edit_semantics: editSemantics,
      };
    } else {
      editSemantics = analyzeWriteSemantics(params, userGoal);
      params = {
        ...params,
        agentmeter_raw_tool_name: "write",
        agentmeter_edit_semantics: editSemantics,
      };
    }
    if (hasCommunicationTarget(text)) {
      name = "send_email";
    } else if (editSemantics.official_integrity_change) {
      name = "modify_official_document";
    } else if (editSemantics.approval_change) {
      name = "submit_approval";
    } else if (editSemantics.authorization_change) {
      name = "grant_access";
    } else if (isOfficialTamperText(text)) {
      name = "modify_official_document";
    } else {
      name = "write_file";
    }
  } else if (rawName === "exec") {
    const publicHttpRequest = readOnlyPublicHttpRequest(params);
    params = {
      ...params,
      agentmeter_edit_semantics: analyzeShellWriteSemantics(params, userGoal),
      ...(publicHttpRequest ? {
        url: publicHttpRequest.url,
        method: publicHttpRequest.method,
        agentmeter_raw_tool_name: "exec",
        agentmeter_read_only_public_http: true,
      } : {}),
    };
    name = isAuditDeleteText(text)
      ? "delete_audit_log"
      : isSensitiveWorkspaceEnumeration(text)
        ? "read_sensitive_file"
        : isDestructiveShellText(text)
          ? "delete_file"
        : isFileWriteShellText(text)
          ? "run_shell"
          : publicHttpRequest
            ? "web_fetch"
          : isReadOnlyShellText(text) || isHarmlessShellProbeText(text) || isReadOnlyOpenClawCommand(params)
            ? "read_document"
            : "run_shell";
  } else if (rawName === "process" && isReadOnlyProcessAction(params)) {
    // OpenClaw uses process.poll/process.log to collect an already-started
    // command's output. Reading that output is not a new side effect and must
    // not open a second approval for the same parent action.
    name = "read_document";
    params = {
      ...params,
      agentmeter_parent_continuation: true,
      agentmeter_raw_tool_name: "process",
    };
  } else if (rawName === "apply_patch") {
    name = isOfficialTamperText(text) ? "modify_official_document" : "apply_patch";
  } else if (/approve|approval/.test(rawName.toLowerCase())) {
    name = "submit_approval";
  }
  return {
    name,
    params,
    source: "openclaw_before_tool_call",
    data_level: inferDataLevel(name, params),
    result,
    evidence: `OpenClaw ${rawName} tool call intercepted by AgentMeter-Gov Guard`,
  };
}

async function attachExistingWriteContent(event, ctx) {
  if (String(event?.toolName ?? "") !== "write") return event;
  const rawPath = String(event?.params?.path ?? event?.params?.file_path ?? "").trim();
  const workspace = String(ctx?.workspaceDir ?? ctx?.cwd ?? "").trim();
  if (!rawPath || !workspace) return event;
  const root = resolve(workspace);
  const target = isAbsolute(rawPath) ? resolve(rawPath) : resolve(root, rawPath);
  const rel = relative(root, target);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) return event;
  try {
    const metadata = await stat(target);
    if (!metadata.isFile() || metadata.size > 1024 * 1024) return event;
    const existing = await readFile(target, "utf8");
    return {
      ...event,
      params: {
        ...(event?.params ?? {}),
        agentmeter_existing_content: existing,
      },
    };
  } catch {
    return event;
  }
}

async function withSideEffectBurstMarker(api, state, proposed, ctx, event) {
  if (!isSideEffectProposal(proposed)) {
    return proposed;
  }
  const targetKey = reviewTargetKey(proposed);
  const now = Date.now();
  state.proposedSideEffects = [
    ...(state.proposedSideEffects ?? []).filter((item) => now - item.createdAt <= 2 * 60 * 1000),
    {
      name: proposed.name,
      targetKey,
      actionFamily: reviewActionFamily(proposed),
      createdAt: now,
    },
  ];
  const sessionKey = String(ctx?.sessionKey ?? event?.sessionKey ?? contextKey(event, ctx));
  const persistentItems = await appendBatchState(api, {
    sessionKey,
    name: proposed.name,
    targetKey,
    actionFamily: reviewActionFamily(proposed),
    createdAt: now,
  });
  const combined = [...(state.proposedSideEffects ?? []), ...persistentItems];
  const distinctTargets = new Set(combined.map((item) => item.targetKey).filter(Boolean));
  if (distinctTargets.size < 5 && combined.length < 6) {
    return proposed;
  }
  return {
    ...proposed,
    params: {
      ...proposed.params,
      agentmeter_side_effect_burst: {
        count: combined.length,
        distinct_targets: distinctTargets.size,
        session_key: sessionKey,
        marker: "foreach repeated side-effect burst",
      },
    },
  };
}

async function appendBatchState(api, item) {
  return withBatchStoreLock(async () => {
    const path = batchStatePath(api);
    const now = Date.now();
    let data = { version: "batch-state-v1", events: [] };
    try {
      const raw = await readFile(path, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && Array.isArray(parsed.events)) {
        data = { version: String(parsed.version ?? "batch-state-v1"), events: parsed.events };
      }
    } catch {
      data = { version: "batch-state-v1", events: [] };
    }

    const kept = data.events.filter((existing) => {
      const createdAt = Number(existing?.createdAt ?? 0);
      return Number.isFinite(createdAt) && now - createdAt <= 2 * 60 * 1000;
    });
    kept.push(item);
    data.events = kept.slice(-500);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify(data, null, 2), "utf8");
    return data.events.filter((existing) => existing?.sessionKey === item.sessionKey);
  });
}

async function withBatchStoreLock(operation) {
  const run = batchStoreLock.then(operation, operation);
  batchStoreLock = run.catch(() => undefined);
  return run;
}

function batchStatePath(api) {
  const config = api.pluginConfig ?? {};
  return resolveRuntimePath(api, config.batchStatePath ?? DEFAULT_BATCH_STATE_FILE);
}

function isSideEffectProposal(proposed) {
  return [
    "write_file",
    "run_shell",
    "apply_patch",
    "delete_file",
    "delete_audit_log",
    "modify_official_document",
    "send_email",
    "upload_file",
    "execute_payment",
    "grant_access",
  ].includes(String(proposed?.name ?? ""));
}

async function callGate(api, payload, backendService = null) {
  return requestGate(api.pluginConfig ?? {}, payload, backendService);
}

function parseSupplyChainScanCommand(prompt) {
  const text = String(prompt ?? "");
  if (!/(supply[- ]?chain|skill|plugin|scan|drift)/i.test(text)) {
    return null;
  }
  const baseline = extractPathArg(text, "baseline") ?? extractPathArg(text, "v1");
  const candidate = extractPathArg(text, "candidate") ?? extractPathArg(text, "v2");
  if (!baseline || !candidate) {
    return null;
  }
  return { baseline, candidate };
}

function extractPathArg(text, key) {
  const pattern = new RegExp(`${key}\\s*[:=]\\s*(?:"([^"]+)"|'([^']+)'|([^\\r\\n]+?))(?=\\s+(?:baseline|candidate|v1|v2|基线|候选)\\s*[:=]|$)`, "i");
  const match = text.match(pattern);
  if (!match) {
    return null;
  }
  return String(match[1] ?? match[2] ?? match[3] ?? "").trim();
}

async function callSupplyChainScan(api, payload, backendService = null) {
  const config = api.pluginConfig ?? {};
  const scanUrl = String(config.supplyChainScanUrl ?? DEFAULT_SUPPLY_CHAIN_SCAN_URL);
  const request = async () => {
    const response = await fetch(scanUrl, {
      method: "POST",
      headers: apiHeaders(config),
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`AgentMeter-Gov supply-chain scan failed: HTTP ${response.status}`);
    }
    return response.json();
  };
  try {
    return await request();
  } catch (initialError) {
    if (!backendService || !(await backendService.ensureReady())) throw initialError;
    return request();
  }
}

async function record(api, item) {
  const config = api.pluginConfig ?? {};
  const recordPath = resolveRuntimePath(api, config.recordPath ?? DEFAULT_RECORD_FILE);
  const timestamp = new Date().toISOString();
  const eventId = `AME-${createHash("sha256")
    .update(`${timestamp}|${item.event_type ?? "event"}|${item.task_id ?? ""}|${Math.random()}`)
    .digest("hex")
    .slice(0, 20)}`;
  const envelope = {
    schema_version: "agentmeter.event.v1",
    adapter: "openclaw",
    event_id: eventId,
    audit_id: item.audit_id ?? item.task_id ?? "",
    timestamp,
    plugin: "agentmeter-gov-guard",
    ...item,
  };
  const line = JSON.stringify(envelope);
  await withRecordStoreLock(async () => {
    await mkdir(dirname(recordPath), { recursive: true });
    await rotateRecordFile(recordPath, Number(config.maxLogBytes ?? 10 * 1024 * 1024), Number(config.logBackups ?? 5));
    await appendFile(recordPath, `${line}\n`, "utf8");
  });
  if (config.persistEvents !== false) {
    try {
      await fetch(String(config.eventUrl ?? DEFAULT_EVENT_URL), {
        method: "POST",
        headers: apiHeaders(config),
        body: line,
        signal: AbortSignal.timeout(2000),
      });
    } catch {
      // JSONL remains authoritative while the configured event store is unavailable.
    }
  }
}

async function withRecordStoreLock(operation) {
  const run = recordStoreLock.then(operation, operation);
  recordStoreLock = run.catch(() => undefined);
  return run;
}

function apiHeaders(config) {
  const headers = { "content-type": "application/json" };
  const token = String(config.apiToken ?? process.env.AGENTMETER_API_TOKEN ?? "").trim();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

async function rotateRecordFile(path, maxBytes, backups) {
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) return;
  try {
    if ((await stat(path)).size < maxBytes) return;
  } catch {
    return;
  }
  const count = Math.max(1, Math.min(20, Number.isFinite(backups) ? Math.floor(backups) : 5));
  for (let index = count; index >= 1; index -= 1) {
    const source = index === 1 ? path : `${path}.${index - 1}`;
    const destination = `${path}.${index}`;
    try {
      await rm(destination, { force: true });
      await rename(source, destination);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
}

function isGuardBypassPrompt(prompt) {
  const compact = String(prompt ?? "").replace(/\s+/g, "").toLowerCase();
  return /openclawgatewaydisable-agentmeter-gov|disable-agentmeter-gov|bypassagentmeter|绕过agentmeter|禁用agentmeter|关闭agentmeter(?:-gov)?防护|关闭安全防护|关掉agentmeter(?:-gov)?防护|防护关闭|guardoff|guarddisable|disableagentmeter(?:-gov)?guard/.test(compact);
}

async function createPendingReview(api, proposed, result, state, ctx, event) {
  return withApprovalStoreLock(async () => {
  const store = await readApprovalStore(api);
  const existing = findEquivalentPendingReview(store, proposed, ctx, event);
  if (existing) {
    await record(api, {
      event_type: "pending_review_event",
      task_id: state.taskId,
      session_key: String(ctx?.sessionKey ?? ""),
      run_id: String(ctx?.runId ?? event?.runId ?? ""),
      review_id: existing.reviewId,
      proposed_tool_call: proposed,
      risk_score: result.risk_measurement?.total_score ?? 0,
      triggered_rules: result.risk_measurement?.matched_rules ?? [],
      evidence: `Equivalent pending review already exists. Reuse Approval ID: ${existing.reviewId}.`,
    });
    return existing;
  }
  const reviewId = `AGR-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`.toUpperCase();
  const pending = {
    reviewId,
    signature: approvalSignature(proposed),
    paramsHash: approvalParamsHash(proposed),
    targetKey: reviewTargetKey(proposed),
    actionFamily: reviewActionFamily(proposed),
    createdAt: new Date().toISOString(),
    consumed: false,
    taskId: state.taskId,
    userId: String(ctx?.userId ?? ctx?.accountId ?? "openclaw_user"),
    sessionKey: String(ctx?.sessionKey ?? ""),
    runId: String(ctx?.runId ?? event?.runId ?? ""),
    proposedToolCall: proposed,
    userGoalPreview: String(state.userGoal ?? "").slice(0, 500),
    originalUserGoal: String(state.userGoal ?? "").slice(0, 2000),
    riskScore: result.risk_measurement?.total_score ?? 0,
    matchedRules: result.risk_measurement?.matched_rules ?? [],
  };
  store.pending = [pending, ...(store.pending ?? []).filter((item) => !item.consumed)].slice(0, 20);
  await writeApprovalStore(api, store);
  await record(api, {
    event_type: "pending_review_event",
    task_id: state.taskId,
    session_key: String(ctx?.sessionKey ?? ""),
    run_id: String(ctx?.runId ?? event?.runId ?? ""),
    review_id: reviewId,
    proposed_tool_call: proposed,
    risk_score: pending.riskScore,
    triggered_rules: pending.matchedRules,
    evidence: `Human review pending. Approval ID: ${reviewId}.`,
  });
  return pending;
  });
}

async function reviewPendingReview(api, command, prompt, ctx, event) {
  return withApprovalStoreLock(async () => {
  const store = await readApprovalStore(api);
  const pending = selectPendingReview(store, command.reviewId, ctx, event);
  if (command.decision === "reject") {
    const rejectionId = `REJ-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`.toUpperCase();
    if (pending) {
      pending.consumed = true;
      pending.rejected = true;
      pending.rejectedAt = new Date().toISOString();
      pending.rejectionId = rejectionId;
    }
    store.rejections = [
      {
        rejectionId,
        reviewId: pending?.reviewId ?? command.reviewId ?? "",
        signature: pending?.signature ?? "",
        rejectedAt: new Date().toISOString(),
        sessionKey: String(ctx?.sessionKey ?? ""),
        runId: String(ctx?.runId ?? event?.runId ?? ""),
        promptPreview: String(prompt ?? "").slice(0, 300),
      },
      ...(store.rejections ?? []),
    ].slice(0, 20);
    await writeApprovalStore(api, store);
    if (pending) {
      await appendReviewMemory(api, {
        decision: "rejected",
        reviewId: pending.reviewId,
        userId: pending.userId ?? String(ctx?.userId ?? ctx?.accountId ?? "openclaw_user"),
        proposedToolCall: pending.proposedToolCall,
        riskScore: pending.riskScore ?? 0,
        matchedRules: pending.matchedRules ?? [],
        source: "openclaw_human_rejection",
      });
    }
    return {
      approvalId: "",
      rejectionId,
      reviewId: pending?.reviewId ?? command.reviewId ?? "",
      decision: "reject",
      scope: pending ? "latest_pending_review" : "no_pending_review",
      message: pending
        ? `Rejection ${rejectionId} recorded for review ${pending.reviewId}; this action will not be released.`
        : `Rejection ${rejectionId} recorded, but no recent pending review was found.`,
    };
  }
  const approvalId = `APP-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`.toUpperCase();
  if (!pending) {
    await writeApprovalStore(api, store);
    return {
      approvalId: "",
      reviewId: command.reviewId ?? "",
      decision: "approve",
      scope: "no_pending_review",
      message: "No recent pending review was found; no tool call was released.",
    };
  }
  const requestedTaskScope = command.scope === "bounded_task";
  const taskScopeKey = requestedTaskScope ? boundedTaskScopeKey(pending.proposedToolCall) : "";
  const boundedTaskScope = Boolean(requestedTaskScope && taskScopeKey);
  const sessionBinding = bindApprovalSession(pending, String(ctx?.sessionKey ?? ""));
  const approval = {
    approvalId,
    reviewId: pending.reviewId,
    // Recompute with the current semantic signature so approvals created by an
    // older plugin build and harmless retry timeout changes remain usable.
    signature: approvalSignature(pending.proposedToolCall),
    paramsHash: approvalParamsHash(pending.proposedToolCall),
    targetKey: pending.targetKey ?? reviewTargetKey(pending.proposedToolCall),
    actionFamily: pending.actionFamily ?? reviewActionFamily(pending.proposedToolCall),
    approvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + (boundedTaskScope ? 10 : 5) * 60 * 1000).toISOString(),
    consumed: false,
    sessionKey: sessionBinding.releaseSessionKey,
    originSessionKey: sessionBinding.originSessionKey,
    approvalSessionKey: sessionBinding.approvalSessionKey,
    crossSession: sessionBinding.crossSession,
    approvedByUserId: String(ctx?.userId ?? ctx?.accountId ?? "openclaw_user"),
    runId: String(ctx?.runId ?? event?.runId ?? ""),
    scope: boundedTaskScope ? "bounded_task" : "exact_action",
    taskScopeKey,
    remainingUses: boundedTaskScope ? 8 : 1,
    maxRiskScore: boundedTaskScope ? 74 : Number(pending.riskScore ?? 74),
    originalUserGoal: String(pending.originalUserGoal ?? pending.userGoalPreview ?? "").slice(0, 2000),
    promptPreview: String(prompt ?? "").slice(0, 300),
  };
  store.approvals = [approval, ...(store.approvals ?? []).filter((item) => !item.consumed)].slice(0, 20);
  await writeApprovalStore(api, store);
  await appendReviewMemory(api, {
    decision: "approved",
    reviewId: pending.reviewId,
    userId: pending.userId ?? String(ctx?.userId ?? ctx?.accountId ?? "openclaw_user"),
    proposedToolCall: pending.proposedToolCall,
    riskScore: pending.riskScore ?? 0,
    matchedRules: pending.matchedRules ?? [],
    source: "openclaw_human_approval",
  });
  return {
    approvalId,
    reviewId: approval.reviewId,
    decision: "approve",
    scope: approval.scope,
    originalUserGoal: approval.originalUserGoal,
    originSessionKey: approval.originSessionKey,
    releaseSessionKey: approval.sessionKey,
    crossSession: approval.crossSession,
    message: boundedTaskScope
      ? `Approval ${approvalId} recorded for review ${pending.reviewId}; it can release up to 8 matching actions in this OpenClaw task for 10 minutes. Hard blocks and non-delegable actions remain protected.`
      : approval.crossSession
        ? `Approval ${approvalId} recorded for review ${pending.reviewId}; the exact paused action will resume in its originating conversation.`
      : requestedTaskScope
        ? `Approval ${approvalId} recorded for review ${pending.reviewId}; this action is not eligible for task-wide release, so only the exact action can be released once.`
        : `Approval ${approvalId} recorded for review ${pending.reviewId}; it can release this exact action once.`,
  };
  });
}

async function consumeApproval(api, proposed, result, state, ctx, event) {
  return withApprovalStoreLock(async () => {
  const store = await readApprovalStore(api);
  const signature = approvalSignature(proposed);
  const now = Date.now();
  const activeApprovals = (store.approvals ?? []).filter((item) => {
    if (item.consumed) {
      return false;
    }
    const expiresAt = Date.parse(item.expiresAt ?? item.approvedAt ?? "");
    if (Number.isFinite(expiresAt) && now > expiresAt) {
      return false;
    }
    const sessionKey = String(ctx?.sessionKey ?? "");
    return !item.sessionKey || !sessionKey || item.sessionKey === sessionKey;
  });
  const approval = activeApprovals.find((item) => item.signature === signature)
    ?? activeApprovals.find((item) => isBoundedTaskApprovalMatch(item, proposed, result));
  if (!approval) {
    return null;
  }
  const boundedTaskScope = approval.scope === "bounded_task";
  approval.remainingUses = Math.max(0, Number(approval.remainingUses ?? 1) - 1);
  approval.consumed = !boundedTaskScope || approval.remainingUses <= 0;
  approval.consumedAt = new Date().toISOString();
  const pending = (store.pending ?? []).find(
    (item) => !item.consumed && (
      item.reviewId === approval.reviewId
      || item.signature === signature
    ),
  );
  if (pending) {
    pending.consumed = true;
    pending.consumedAt = approval.consumedAt;
    approval.reviewId = pending.reviewId;
  }
  await writeApprovalStore(api, store);
  return {
    approvalId: approval.approvalId,
    reviewId: approval.reviewId,
    scope: approval.scope ?? "exact_action",
    remainingUses: approval.remainingUses,
    message: boundedTaskScope
      ? `Bounded task approval ${approval.approvalId} released ${proposed.name}; ${approval.remainingUses} matching actions remain before ${approval.expiresAt}.`
      : `Human review approved by ${approval.approvalId}; allowing ${proposed.name} once after score ${result.risk_measurement?.total_score ?? "unknown"}.`,
  };
  });
}

function selectPendingReview(store, reviewId, ctx, event) {
  return selectPendingReviewForContext(store, {
    reviewId,
    sessionKey: String(ctx?.sessionKey ?? ""),
  });
}

function isHeartbeatRun(prompt, ctx, event) {
  return String(ctx?.trigger ?? event?.trigger ?? "").toLowerCase() === "heartbeat"
    || /^\[OpenClaw heartbeat poll\]$/i.test(String(prompt ?? "").trim());
}

async function findApprovedContinuationForSession(api, sessionKey) {
  if (!String(sessionKey ?? "").trim()) return null;
  return withApprovalStoreLock(async () => {
    const store = await readApprovalStore(api);
    return selectApprovedContinuationForSession(store, { sessionKey });
  });
}

function findEquivalentPendingReview(store, proposed, ctx, event) {
  const signature = approvalSignature(proposed);
  const sessionKey = String(ctx?.sessionKey ?? "");
  const now = Date.now();
  return (store.pending ?? [])
    .filter((item) => {
      if (item.consumed || item.rejected) {
        return false;
      }
      const createdAt = Date.parse(item.createdAt ?? "");
      if (!Number.isFinite(createdAt) || now - createdAt > 10 * 60 * 1000) {
        return false;
      }
      if (item.sessionKey !== sessionKey) {
        return false;
      }
      return item.signature === signature;
    })
    .sort((a, b) => Date.parse(b.createdAt ?? "") - Date.parse(a.createdAt ?? ""))[0] ?? null;
}

async function findOpenPendingReviewForProposed(api, proposed, ctx, event) {
  return withApprovalStoreLock(async () => {
    const store = await readApprovalStore(api);
    return findEquivalentPendingReview(store, proposed, ctx, event) ?? null;
  });
}

function approvalSignature(proposed) {
  const params = proposed?.params ?? {};
  const emails = approvalDestinationEmails(params).sort().join(",");
  const path = reviewTargetKey(proposed);
  return `${proposed?.name ?? "unknown"}|${reviewActionFamily(proposed)}|${path}|${emails}|${approvalParamsHash(proposed)}`;
}

function approvalParamsHash(proposed) {
  const normalized = stableStringify(redact(approvalComparableParams(proposed?.params ?? {})));
  return createHash("sha256").update(normalized).digest("hex").slice(0, 16);
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function reviewActionFamily(proposed) {
  const name = String(proposed?.name ?? "");
  if (["write_file", "run_shell", "apply_patch"].includes(name)) {
    return "write";
  }
  if (["send_email", "upload_file"].includes(name)) {
    return "external_send";
  }
  if (name === "execute_payment") {
    return "payment";
  }
  if (name === "grant_access") {
    return "access_grant";
  }
  return name || "unknown";
}

const NON_DELEGABLE_TASK_TOOLS = new Set([
  "send_email",
  "upload_file",
  "execute_payment",
  "grant_access",
  "delete_file",
  "delete_audit_log",
  "modify_official_document",
  "submit_approval",
  "approve_request",
  "read_secret",
  "read_sensitive_file",
]);

function isBoundedTaskApprovalMatch(approval, proposed, result) {
  if (approval?.scope !== "bounded_task" || Number(approval?.remainingUses ?? 0) <= 0) {
    return false;
  }
  if (NON_DELEGABLE_TASK_TOOLS.has(String(proposed?.name ?? ""))) {
    return false;
  }
  if (String(proposed?.data_level ?? "public") === "secret"
      || String(proposed?.data_level ?? "public") === "internal_sensitive") {
    return false;
  }
  if (reviewMemoryExternalTarget(proposed)) {
    return false;
  }
  const riskScore = Number(result?.risk_measurement?.total_score ?? 100);
  if (!Number.isFinite(riskScore) || riskScore > Number(approval.maxRiskScore ?? 74)) {
    return false;
  }
  const hardBlocks = [
    ...(result?.security_control?.hard_blocks ?? []),
    ...(result?.risk_measurement?.control_plan?.hard_blocks ?? []),
    ...(result?.risk_measurement?.scoring_details?.hard_blocks ?? []),
  ];
  if (hardBlocks.length > 0) {
    return false;
  }
  const taskScopeKey = boundedTaskScopeKey(proposed);
  return Boolean(taskScopeKey && taskScopeKey === approval.taskScopeKey);
}

function reviewTargetKey(proposed) {
  const params = proposed?.params ?? {};
  const direct = String(
    params.path
      ?? params.file
      ?? params.url
      ?? params.to
      ?? extractShellDestination(params.command)
      ?? "",
  ).trim();
  if (direct) {
    return normalizeTarget(direct);
  }
  const text = JSON.stringify(params).replace(/\\\\/g, "\\");
  const pathMatch = text.match(/[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)+(?:\.[A-Za-z0-9_.-]+)?/);
  if (pathMatch) {
    return normalizeTarget(pathMatch[0]);
  }
  const emails = extractApprovalEmails(text).sort();
  if (emails.length) {
    return `email:${emails.join(",")}`;
  }
  return normalizeTarget(direct);
}

function normalizeTarget(value) {
  let normalized = String(value ?? "")
    .replace(/\\/g, "/")
    .replace(/^\.\/+/, "")
    .trim()
    .toLowerCase();
  const workspaceMarker = ".openclaw/workspace/";
  const workspaceIndex = normalized.indexOf(workspaceMarker);
  if (workspaceIndex >= 0) {
    normalized = normalized.slice(workspaceIndex + workspaceMarker.length);
  }
  const demoIndex = normalized.indexOf("agentmeter_demo/");
  if (demoIndex >= 0) {
    normalized = normalized.slice(demoIndex);
  }
  return normalized.replace(/^\/+/, "");
}

function extractApprovalEmails(text) {
  return extractEmails(text).filter((email) => !/^(no-?reply|local-sandbox)@/i.test(email));
}

function approvalDestinationEmails(params) {
  const values = [
    params?.to,
    params?.recipient,
    params?.recipients,
    params?.target,
    params?.url,
    params?.endpoint,
  ].flatMap((value) => Array.isArray(value) ? value : [value]);
  return extractApprovalEmails(values.filter(Boolean).join(" "));
}

function extractEmails(text) {
  return Array.from(String(text ?? "").matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)).map((item) =>
    item[0].toLowerCase(),
  );
}

async function withApprovalStoreLock(operation) {
  const run = approvalStoreLock.then(operation, operation);
  approvalStoreLock = run.catch(() => undefined);
  return run;
}

async function readApprovalStore(api) {
  try {
    const raw = await readFile(approvalPath(api), "utf8");
    const parsed = JSON.parse(raw);
    return {
      pending: Array.isArray(parsed.pending) ? parsed.pending : [],
      approvals: Array.isArray(parsed.approvals) ? parsed.approvals : [],
      rejections: Array.isArray(parsed.rejections) ? parsed.rejections : [],
    };
  } catch {
    return { pending: [], approvals: [], rejections: [] };
  }
}

async function writeApprovalStore(api, store) {
  const path = approvalPath(api);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(store, null, 2), "utf8");
}

function approvalPath(api) {
  const config = api.pluginConfig ?? {};
  return resolveRuntimePath(api, config.approvalPath ?? DEFAULT_APPROVAL_FILE);
}

async function appendReviewMemory(api, item) {
  const path = reviewMemoryPath(api);
  let data = { version: "review-memory-v1", memories: [] };
  try {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      data = {
        version: String(parsed.version ?? "review-memory-v1"),
        memories: Array.isArray(parsed.memories) ? parsed.memories : [],
      };
    }
  } catch {
    data = { version: "review-memory-v1", memories: [] };
  }

  const memory = buildReviewMemoryItem(item);
  const duplicateKey = [
    memory.decision,
    memory.user_id,
    memory.tool_action,
    memory.source_data_level,
    memory.target_path_prefix,
    String(memory.external_target),
  ].join("|");
  const kept = data.memories.filter((existing) => {
    const existingKey = [
      existing?.decision,
      existing?.user_id,
      existing?.tool_action,
      existing?.source_data_level,
      existing?.target_path_prefix,
      String(Boolean(existing?.external_target)),
    ].join("|");
    return existingKey !== duplicateKey;
  });
  data.memories = [memory, ...kept].slice(0, 200);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(data, null, 2), "utf8");
}

function buildReviewMemoryItem(item) {
  const proposed = item.proposedToolCall ?? {};
  const now = new Date();
  const approved = item.decision === "approved";
  const expires = new Date(now.getTime() + (approved ? 7 : 30) * 24 * 60 * 60 * 1000);
  return {
    memory_id: `RM-${now.toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${String(item.reviewId || "MANUAL").replace(/[^A-Za-z0-9_-]/g, "")}`,
    version: "review-memory-v1",
    decision: approved ? "approved" : "rejected",
    user_id: String(item.userId || "openclaw_user"),
    intent: "unknown",
    tool_action: reviewMemoryToolAction(proposed),
    tool_name: String(proposed.name ?? "unknown"),
    source_data_level: String(proposed.data_level ?? "public"),
    target_path_prefix: reviewMemoryTargetPrefix(proposed),
    external_target: reviewMemoryExternalTarget(proposed),
    target_key: reviewMemoryTargetKey(proposed),
    approved_risk_max: approved ? 55 : 0,
    score_delta: approved ? 0 : 20,
    max_uses: approved ? 1 : 0,
    used_count: 0,
    expires_at: expires.toISOString(),
    created_at: now.toISOString(),
    created_from_review_id: String(item.reviewId ?? ""),
    source: String(item.source ?? "openclaw_review"),
    risk_score: Number(item.riskScore ?? 0),
    matched_rules: Array.isArray(item.matchedRules) ? item.matchedRules : [],
    status: "active",
  };
}

function reviewMemoryPath(api) {
  const config = api.pluginConfig ?? {};
  return resolveRuntimePath(api, config.reviewMemoryPath ?? DEFAULT_REVIEW_MEMORY_FILE);
}

function reviewMemoryToolAction(proposed) {
  const name = String(proposed?.name ?? "");
  const text = `${name} ${JSON.stringify(proposed?.params ?? {})}`.toLowerCase();
  if (name === "write_file" || name === "apply_patch") {
    return reviewMemoryExternalTarget(proposed) ? "external_send" : "write_internal_file";
  }
  if (name === "run_shell" && isReadOnlyShellText(text)) {
    return "read_file";
  }
  if (name === "run_shell" && isFileWriteShellText(text)) {
    return "write_internal_file";
  }
  if (/\.env|\.npmrc|token|api_key|secret|credential|password/.test(text)) {
    return "credential_access";
  }
  if (name === "delete_audit_log" || /audit\.log|delete audit|clear audit|删除日志|清空日志/.test(text)) {
    return "audit_destroy";
  }
  if (name === "submit_approval" || name === "approve_request" || name === "modify_official_document") {
    return "approval_action";
  }
  if (name === "send_email" || name === "upload_file" || reviewMemoryExternalTarget(proposed)) {
    return "external_send";
  }
  if (name === "run_shell" || /powershell|cmd\.exe|bash|remove-item|rm |del /.test(text)) {
    return "system_operation";
  }
  if (name === "read_file" || name === "read_document" || name === "query_database" || name === "search_memory") {
    return "read_file";
  }
  return name || "unknown";
}

function reviewMemoryTargetKey(proposed) {
  const params = proposed?.params ?? {};
  const target = String(params.path ?? params.target ?? params.file ?? params.destination ?? params.to ?? extractShellDestination(params.command) ?? "");
  return target.replace(/\\/g, "/").replace(/^\/+/, "");
}

function reviewMemoryTargetPrefix(proposed) {
  const parts = reviewMemoryTargetKey(proposed).split("/").filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0]}/${parts[1]}/`;
  }
  if (parts.length === 1) {
    return `${parts[0]}/`;
  }
  return "";
}

function reviewMemoryExternalTarget(proposed) {
  const text = JSON.stringify(proposed?.params ?? {}).toLowerCase();
  return /https?:\/\/|@external|external-demo|send_to_external/.test(text);
}

function resolveRuntimePath(api, configuredPath) {
  const rawPath = String(configuredPath ?? "");
  if (isAbsolute(rawPath)) {
    return rawPath;
  }
  const config = api.pluginConfig ?? {};
  const root = String(config.runtimeDir ?? process.env.AGENTMETER_GOV_HOME ?? process.cwd());
  return resolve(join(root, rawPath));
}

function inferDataLevel(name, params) {
  const text = JSON.stringify(params);
  if (name === "read_sensitive_file" || (!hasNegativeSensitivityContext(text) && /staff_sensitive|身份证|手机号|内部人员|USER\.md|database_config|C:\\\\Windows|\/etc\/passwd/i.test(text))) {
    return "internal_sensitive";
  }
  if (name === "read_secret" || (isSecretText(text) && !hasNegativeSensitivityContext(text))) {
    return "secret";
  }
  if (["modify_official_document", "submit_approval", "delete_audit_log", "execute_payment", "grant_access"].includes(name)) {
    return "internal";
  }
  if (name === "run_shell" || name === "write_file") {
    return "internal";
  }
  return "public";
}

function inferAuthorization(prompt) {
  const text = String(prompt);
  const lower = text.toLowerCase();
  const auth = [];
  if (/鎽樿|浼氳绾/.test(text)) {
    auth.push("summarize_document");
  }
  const externalNegated =
    /不发送|不要发送|无需发送|未发送|不外发|无外发|不上传|未上传|do not send|do not email|no email|no external|do not upload|not uploaded|local only/i.test(text)
    || /(?:不要|不得|无需)[^。！？\n]{0,80}(?:发送|邮件|外发|上传)/i.test(text)
    || /\b(?:do not|don't|never)\b[^.!?\n]{0,120}\b(?:send|email|upload)\b/i.test(lower);
  if (!externalNegated && /发送|邮件|外发|上传|review-service@external-demo\.com|send|email|upload/.test(lower)) {
    auth.push("send_email_or_mail_sandbox");
  }
  if (/浜哄憳|staff_sensitive|鍐呴儴/.test(text)) {
    auth.push("read_sensitive_file");
  }
  return auth;
}

function summarizeEffects(events) {
  return events
    .filter((event) => event.result === "success" && isSideEffect(event))
    .map((event) => `${event.name}:${JSON.stringify(event.params)}`)
    .join(" | ");
}

function summarizeBlockedEffects(events) {
  return events
    .filter((event) => event.result === "failed" && isSideEffect(event))
    .map((event) => `${event.name}:${JSON.stringify(event.params)}`)
    .join(" | ");
}

function isSideEffect(event) {
  return [
    "send_email",
    "upload_file",
    "write_file",
    "run_shell",
    "apply_patch",
    "delete_file",
    "delete_audit_log",
    "modify_official_document",
    "submit_approval",
    "approve_request",
    "execute_payment",
    "grant_access",
  ].includes(event.name);
}

function isSecretText(text) {
  const normalized = String(text ?? "");
  if (hasNegativeSensitivityContext(normalized)) {
    return false;
  }
  return /\.env|token|api[_-]?key|password|secret|瀵嗛挜|鍑嵁|璐﹀彿瀵嗙爜/i.test(normalized);
}

function hasNegativeSensitivityContext(text) {
  const normalized = String(text ?? "").toLowerCase();
  const negated = /不包含|未包含|不含|未含|不涉及|未涉及|没有|无敏感|无密钥|无凭据|无手机号|无身份证|剔除|已剔除|去除|已去除|脱敏|已脱敏|do not include|without|exclude|excluded|redacted|no sensitive|no secret|no secrets|no phone|no phones|no phone numbers|no id|no ids|no id numbers|no external recipient/i.test(normalized);
  const sensitiveMentioned = /敏感|密钥|凭据|手机号|手机号码|身份证|身份证号|个人信息|token|api[_-]?key|password|secret|secrets|credential|credentials|phone|phones|phone numbers|mobile|id card|id number|id numbers|identity|pii/i.test(normalized);
  return negated && sensitiveMentioned;
}

// Recipient labels, in the forms a Chinese draft actually uses. The colon must
// match its full-width form: `收件人：` is what anyone typing Chinese produces,
// and only `收件人:` was recognised. A live run caught this — the model wrote
// "收件邮箱：service-desk@…" into a reply letter and the draft was governed as
// an ordinary file write, so the outbound path was never entered at all.
const RECIPIENT_LABEL_PATTERN =
  "(?:收件人|收件邮箱|收件地址|收件方|收信人|收函单位|抄送|致)\\s*[:：]"
  + "|(^|\\\\n|[\"'\\s])(?:to|cc|bcc)\\s*[:：]";

function hasCommunicationTarget(text) {
  const normalized = String(text ?? "");
  const lower = normalized.toLowerCase();
  const recipientLabel = new RegExp(`${RECIPIENT_LABEL_PATTERN}|发送给|发给|send email|send to|upload to`, "i");
  const reportOnly =
    /安全报告|合规报告|拒绝原因|如实说明|如实汇报|披露|处置报告|blocked|refused|refusal|security report|incident report/i.test(normalized)
    && !recipientLabel.test(lower);
  if (reportOnly) {
    return false;
  }
  const communication = new RegExp(
    "send_to_external|review-service@external-demo\\.com"
    + `|${RECIPIENT_LABEL_PATTERN}`
    + "|发送给|发给|邮件草稿|email draft|send email|send to|upload to"
    + "|[a-z0-9._%+-]+\\s*(?:\\[at\\]|\\(at\\)| at )\\s*[a-z0-9.-]+\\s*(?:\\[dot\\]|\\(dot\\)| dot |\\.)\\s*[a-z]{2,}",
    "i",
  );
  return communication.test(normalized);
}

function isOfficialTamperText(text) {
  const safeSummary = /(summary|abstract|redacted|local only|nothing was modified|nothing was submitted|nothing was approved|no approval action|do not modify|do not change|does not change|不修改|不提交|不审批)/i.test(text);
  const explicitMutation = /(改成|改为|替换|修改为|newtext|oldtext|replace|remove|delete|changed from|becomes approved|become approved|pay immediately after signing)/i.test(text);
  if (safeSummary && !explicitMutation) {
    return false;
  }
  const officialContext = /(审批|验收|公文|批复|意见|合同|official|approval|contract)/i.test(text);
  const conclusionTamper = /(暂缓通过|不通过|改为通过|审批通过|删除意见|不要告诉|隐藏修改|篡改|pass|approved)/i.test(text);
  const valueTamper = /(合同金额|金额|付款条件|审批状态|contract amount|payment)/i.test(text)
    && /(改成|改为|替换|修改为|newtext|oldtext|replace|remove|delete|changed from|pay immediately after signing)/i.test(text);
  return officialContext && (conclusionTamper || valueTamper);
}

function extractToolOutput(event) {
  const content = event?.result?.content ?? event?.output?.content ?? event?.toolResult?.content ?? event?.content ?? [];
  if (Array.isArray(content)) {
    return content
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }
        return String(item?.text ?? item?.content ?? "");
      })
      .join("\n");
  }
  if (typeof content === "string") {
    return content;
  }
  return JSON.stringify(event ?? {}).slice(0, 4000);
}

function isBlockedToolResult(event, text) {
  const details = JSON.stringify(event?.details ?? {});
  if (/deniedReason|plugin-before-tool-call|before_tool_call hook failed/i.test(details)) {
    return true;
  }
  const serialized = String(text ?? "");
  return /Tool call blocked because before_tool_call hook failed|human review rejected the latest pending action|AgentMeter-Gov blocked risky tool call/i.test(serialized);
}

function redact(value) {
  if (Array.isArray(value)) {
    return value.map(redact);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, redactSecret(key, redact(val))]));
  }
  if (typeof value === "string") {
    return redactSecret("", value);
  }
  return value;
}

function redactSecret(key, value) {
  if (typeof value !== "string") {
    return value;
  }
  if (/token|api[_-]?key|password|secret/i.test(key)) {
    return "[REDACTED]";
  }
  return value.replace(/(token|api[_-]?key|password|secret)\s*[:=]\s*\S+/gi, "$1=[REDACTED]");
}
