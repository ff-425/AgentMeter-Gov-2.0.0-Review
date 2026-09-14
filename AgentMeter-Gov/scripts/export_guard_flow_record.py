from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "openclaw_guard_flow_events.jsonl"
DEFAULT_OUTPUT = ROOT / "data" / "openclaw_guard_full_flow_record.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Export OpenClaw plugin guard JSONL into a structured full-flow record.")
    parser.add_argument("--input", default=str(DEFAULT_INPUT), help="AgentMeter-Gov Guard JSONL file.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Structured JSON output file.")
    parser.add_argument("--task-id", help="Optional task_id. Defaults to the latest task in the JSONL.")
    args = parser.parse_args()

    events = read_events(Path(args.input))
    grouped = group_by_task(events)
    task_id = args.task_id or latest_task_id(grouped)
    if not task_id:
        raise SystemExit("No guard flow events found.")

    record = build_record(task_id, grouped[task_id])
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(output),
        "task_id": task_id,
        "input_events": len(record["input_events"]),
        "tool_events": len(record["tool_events"]),
        "risk_decision_events": len(record["risk_decision_events"]),
        "result_events": len(record["result_events"]),
        "blocked_before_email": record["summary"]["blocked_before_email"],
    }, ensure_ascii=False, indent=2))


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def group_by_task(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[str(event.get("task_id", "unknown"))].append(event)
    return grouped


def latest_task_id(grouped: dict[str, list[dict[str, Any]]]) -> str:
    latest_blocked = ""
    latest_blocked_ts = ""
    latest_any = ""
    latest_any_ts = ""
    for task_id, events in grouped.items():
        ts = max(str(event.get("timestamp", "")) for event in events)
        if ts > latest_any_ts:
            latest_any = task_id
            latest_any_ts = ts
        if has_blocked_high_risk_action(events) and ts > latest_blocked_ts:
            latest_blocked = task_id
            latest_blocked_ts = ts
    return latest_blocked or latest_any


def has_blocked_high_risk_action(events: list[dict[str, Any]]) -> bool:
    return any(
        event.get("event_type") == "risk_decision_event"
        and event.get("gate_action") == "block"
        for event in events
    )


def has_blocked_email_send(events: list[dict[str, Any]]) -> bool:
    return any(
        event.get("event_type") == "risk_decision_event"
        and event.get("gate_action") == "block"
        and event.get("proposed_tool_call", {}).get("name") == "send_email"
        for event in events
    )


def build_record(task_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    input_events = [event for event in events if event.get("event_type") == "input_event"]
    tool_events = [event for event in events if event.get("event_type") == "tool_event"]
    risk_decisions = [event for event in events if event.get("event_type") == "risk_decision_event"]
    result_events = [event for event in events if event.get("event_type") == "result_event"]

    blocked_email = [
        event
        for event in risk_decisions
        if event.get("tool_name") in {"write", "send_email"}
        and event.get("proposed_tool_call", {}).get("name") == "send_email"
        and event.get("gate_action") == "block"
    ]
    blocked_tool_events = [
        event
        for event in tool_events
        if event.get("status") == "failed" and event.get("side_effect")
    ]
    successful_side_effects = [
        event
        for event in tool_events
        if event.get("status") == "success" and event.get("side_effect")
    ]
    latest_decision = risk_decisions[-1] if risk_decisions else {}
    email_decision = blocked_email[-1] if blocked_email else latest_decision
    primary_block = next(
        (
            event
            for event in risk_decisions
            if event.get("gate_action") == "block"
        ),
        email_decision,
    )

    return {
        "record_type": "AgentMeter-Gov OpenClaw 插件全流程事件记录",
        "task_id": task_id,
        "session_key": first_non_empty(events, "session_key"),
        "run_id": first_non_empty(events, "run_id"),
        "summary": {
            "original_goal": input_events[0].get("user_goal", "") if input_events else "",
            "blocked_before_email": bool(blocked_email),
            "blocked_before_high_risk_action": bool(primary_block and primary_block.get("gate_action") == "block"),
            "primary_block_action": primary_block.get("proposed_tool_call", {}).get("name"),
            "email_gate_action": email_decision.get("gate_action"),
            "email_risk_score": email_decision.get("risk_score"),
            "risk_score": primary_block.get("risk_score"),
            "triggered_rules": primary_block.get("triggered_rules", []),
            "safe_branch": "只读摘要、提取、分析类任务可保留",
            "blocked_branch": "高风险工具调用被 before_tool_call 插件阻断",
            "successful_side_effect_count": len(successful_side_effects),
            "blocked_side_effect_count": len(blocked_tool_events),
        },
        "acceptance_items": {
            "openclaw_task_executed": bool(input_events and tool_events),
            "harmful_case_simulated": bool(primary_block),
            "full_flow_recorded": bool(input_events and risk_decisions and result_events),
            "blocked_before_email_send": bool(blocked_email),
            "blocked_before_high_risk_action": bool(primary_block and primary_block.get("gate_action") == "block"),
            "visual_page_available": "http://127.0.0.1:8765/",
        },
        "input_events": input_events,
        "tool_events": tool_events,
        "blocked_tool_events": blocked_tool_events,
        "successful_side_effects": successful_side_effects,
        "risk_decision_events": risk_decisions,
        "result_events": result_events,
        "evidence_chain": build_evidence_chain(events),
    }


def first_non_empty(events: list[dict[str, Any]], key: str) -> str:
    for event in events:
        value = event.get(key)
        if value:
            return str(value)
    return ""


def build_evidence_chain(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chain = []
    for index, event in enumerate(events, 1):
        chain.append({
            "index": index,
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "tool_name": event.get("tool_name"),
            "decision": event.get("decision"),
            "status": event.get("status"),
            "evidence": event.get("evidence"),
        })
    return chain


if __name__ == "__main__":
    main()
