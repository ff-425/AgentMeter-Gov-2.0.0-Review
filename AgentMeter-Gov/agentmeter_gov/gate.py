from __future__ import annotations

from dataclasses import asdict
from time import perf_counter
from typing import Any

from .audit import build_audit_report
from .batch_meter import record_batch_observation
from .event_protocol import SCHEMA_VERSION, normalize_gate_request
from .recovery import execute_recovery_plan
from .risk_engine import RiskEngine
from .schema import TaskCase, ToolEvent
from .user_profile import update_user_profile


def evaluate_tool_gate(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a runtime-neutral proposed tool call before it is executed."""
    started = checkpoint = perf_counter()
    timings = {}

    def mark(name):
        nonlocal checkpoint
        now = perf_counter()
        timings[name] = round((now - checkpoint) * 1000, 3)
        checkpoint = now

    payload = normalize_gate_request(payload)
    proposed_event = _parse_event(payload["proposed_tool_call"], default_source="before_tool_call")
    history = [
        _parse_event(item, default_source="history")
        for item in payload.get("history_events", [])
    ]
    case = TaskCase(
        task_id=payload.get("task_id", "live-openclaw-task"),
        title=payload.get("title", "OpenClaw 实时工具调用闸门"),
        user_goal=payload.get("user_goal", ""),
        input_sources=payload.get("input_sources", []),
        events=history + [proposed_event],
        expected_label="live_gate",
        user_id=str(payload.get("user_id") or payload.get("session_key") or "openclaw_user"),
    )
    mark("normalize")
    decision = RiskEngine().evaluate(case, timings=timings)
    mark("risk_evaluation")
    review = decision.action == "human_review"
    blocked = not review and (proposed_event.name in decision.blocked_events or decision.action == "block")
    allowed = not blocked and not review
    gate_action = "allow"
    if review:
        gate_action = "human_review"
    elif blocked:
        gate_action = "block"
    if gate_action == "allow":
        update_user_profile(case, decision)
    mark("profile_update")
    recovery_execution = execute_recovery_plan(decision.control_plan.get("recovery_plan", {}))
    mark("recovery")
    decision.control_plan["recovery_execution"] = recovery_execution
    decision.scoring_details["recovery_execution"] = recovery_execution
    batch_profile_update = record_batch_observation(case, gate_action)
    mark("batch_update")
    decision.control_plan["batch_profile_update"] = batch_profile_update
    decision.scoring_details["batch_profile_update"] = batch_profile_update

    report = build_audit_report(case, decision)
    mark("audit_build")
    result = {
        "schema_version": SCHEMA_VERSION,
        "adapter": payload.get("adapter", "generic"),
        "gate_action": gate_action,
        "allowed": allowed,
        "proposed_tool_call": asdict(proposed_event),
        "risk_measurement": asdict(decision),
        "security_control": decision.control_plan,
        "audit_report": report,
        "intercept_result": {
            "before_tool": proposed_event.name,
            "blocked": gate_action in {"block", "human_review"},
            "reason": decision.matched_rules[:3],
            "control_mode": decision.control_plan.get("policy_mode"),
            "controls": [
                item.get("control_id")
                for item in decision.control_plan.get("controls", [])
                if item.get("control_id")
            ],
        },
        "message": _gate_message(gate_action, proposed_event, decision),
    }
    mark("response_build")
    timings["evaluation_total"] = round((perf_counter() - started) * 1000, 3)
    result["gate_timings_ms"] = timings
    return result


def _parse_event(item: dict[str, Any], default_source: str) -> ToolEvent:
    return ToolEvent(
        name=item["name"],
        params=item.get("params", {}),
        source=item.get("source", default_source),
        data_level=item.get("data_level", "public"),
        result=item.get("result", "proposed"),
        evidence=item.get("evidence", "实时工具调用闸门记录"),
    )


def _gate_message(gate_action: str, event: ToolEvent, decision) -> str:
    explanation = _score_explanation(decision)
    control = _control_explanation(decision)
    if gate_action == "block":
        return f"阻断 {event.name}：风险等级 {decision.level}，分数 {decision.total_score}。{explanation}{control}"
    if gate_action == "human_review":
        return f"{event.name} 需要复核：风险等级 {decision.level}，分数 {decision.total_score}。{explanation}{control}"
    return f"允许 {event.name}：风险等级 {decision.level}，分数 {decision.total_score}。{explanation}{control}"


def _score_explanation(decision) -> str:
    details = getattr(decision, "scoring_details", {}) or {}
    contributions = details.get("factor_contributions", {})
    if not contributions:
        return ""

    top = sorted(
        contributions.items(),
        key=lambda item: item[1].get("contribution", 0),
        reverse=True,
    )[:3]
    factor_text = "；".join(
        f"{code}-{item.get('zh_name', item.get('name'))}: {item.get('score')}×{item.get('weight')}={item.get('contribution')}"
        for code, item in top
    )

    combo = details.get("combo_bonus", 0)
    overrides = details.get("overrides", {})
    override_text = ""
    if overrides.get("hard_blocks"):
        override_text = "；命中硬阻断"
    elif overrides.get("review_required"):
        override_text = "；命中强制复核"

    threshold = details.get("threshold_explanation", {})
    threshold_text = threshold.get("explanation", "")
    return f"主要贡献因子：{factor_text}；组合加分：{combo}{override_text}。阈值解释：{threshold_text}"


def _control_explanation(decision) -> str:
    plan = getattr(decision, "control_plan", {}) or {}
    controls = plan.get("controls", [])
    if not controls:
        return ""
    control_ids = [
        str(item.get("control_id"))
        for item in controls
        if isinstance(item, dict) and item.get("control_id")
    ][:4]
    if not control_ids:
        return ""
    mode = plan.get("policy_mode", decision.action)
    return f"防控策略：{mode}，控制点：{', '.join(control_ids)}。"
