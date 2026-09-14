from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .case_loader import case_to_dict
from .schema import RiskDecision, TaskCase


def build_audit_report(case: TaskCase, decision: RiskDecision) -> dict[str, Any]:
    payload = {
        "report_type": "AgentMeter-Gov 行为计量审计报告",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task": case_to_dict(case),
        "risk_measurement": asdict(decision),
        "audit_completeness": audit_completeness(case, decision),
        "evidence_chain": build_evidence_chain(case, decision),
        "execution_graph": build_execution_graph(case, decision),
    }
    payload["report_hash"] = stable_hash(payload)
    return payload


def audit_completeness(case: TaskCase, decision: RiskDecision) -> dict[str, Any]:
    required = {
        "user_goal",
        "input_source",
        "tool_params",
        "data_level",
        "risk_factors",
        "decision",
        "blocked_events",
        "safe_outputs",
    }
    recorded = set()
    if case.user_goal:
        recorded.add("user_goal")
    if case.input_sources:
        recorded.add("input_source")
    if all(event.params for event in case.events):
        recorded.add("tool_params")
    if all(event.data_level for event in case.events):
        recorded.add("data_level")
    if decision.factors:
        recorded.add("risk_factors")
    if decision.action:
        recorded.add("decision")
    if decision.blocked_events is not None:
        recorded.add("blocked_events")
    if decision.safe_outputs is not None:
        recorded.add("safe_outputs")
    return {
        "required": sorted(required),
        "recorded": sorted(recorded),
        "score": round(len(recorded & required) / len(required), 2),
    }


def build_evidence_chain(case: TaskCase, decision: RiskDecision) -> list[dict[str, Any]]:
    chain = []
    previous = ""
    for index, event in enumerate(case.events, 1):
        item = {
            "index": index,
            "event": event.name,
            "source": event.source,
            "params": event.params,
            "data_level": event.data_level,
            "evidence": event.evidence,
            "previous_hash": previous,
        }
        item["hash"] = stable_hash(item)
        previous = item["hash"]
        chain.append(item)
    final = {
        "index": len(chain) + 1,
        "event": "risk_decision",
        "action": decision.action,
        "total_score": decision.total_score,
        "previous_hash": previous,
    }
    final["hash"] = stable_hash(final)
    chain.append(final)
    return chain


def build_execution_graph(case: TaskCase, decision: RiskDecision) -> dict[str, Any]:
    """Build a node-edge graph for audit replay and risk-path explanation."""

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    task_node_id = "task:current"
    decision_node_id = "decision:current"
    nodes.append(
        {
            "id": task_node_id,
            "type": "task",
            "label": case.title or case.task_id,
            "attributes": {
                "task_id": case.task_id,
                "user_goal": case.user_goal,
                "expected_label": case.expected_label,
                "user_id": case.user_id,
            },
        }
    )

    for index, source in enumerate(case.input_sources, 1):
        source_id = f"source:{index}"
        nodes.append(
            {
                "id": source_id,
                "type": "input_source",
                "label": str(source.get("name") or f"source-{index}"),
                "attributes": {
                    "trust": source.get("trust", "medium"),
                    "source_type": source.get("type", "unknown"),
                    "tags": source.get("tags", []),
                    "content_preview": str(source.get("content", ""))[:240],
                },
            }
        )
        edges.append(
            {
                "id": f"edge:source:{index}:task",
                "type": "provides_context",
                "from": source_id,
                "to": task_node_id,
                "label": "输入来源提供任务上下文",
            }
        )

    previous_event_id = ""
    event_node_ids: list[tuple[str, Any]] = []
    for index, event in enumerate(case.events, 1):
        event_id = f"event:{index}:{event.name}"
        event_node_ids.append((event_id, event))
        nodes.append(
            {
                "id": event_id,
                "type": "tool_event",
                "label": event.name,
                "attributes": {
                    "index": index,
                    "source": event.source,
                    "params": event.params,
                    "data_level": event.data_level,
                    "result": event.result,
                    "evidence": event.evidence,
                    "risk_role": graph_event_risk_role(event),
                    "target": graph_event_target(event),
                },
            }
        )
        edges.append(
            {
                "id": f"edge:task:event:{index}",
                "type": "authorizes_or_triggers",
                "from": task_node_id,
                "to": event_id,
                "label": "用户目标约束工具调用",
            }
        )
        if previous_event_id:
            edges.append(
                {
                    "id": f"edge:event:{index - 1}:event:{index}",
                    "type": "next_step",
                    "from": previous_event_id,
                    "to": event_id,
                    "label": "执行链下一步",
                }
            )
        previous_event_id = event_id

    edges.extend(build_graph_data_flow_edges(event_node_ids))

    nodes.append(
        {
            "id": decision_node_id,
            "type": "risk_decision",
            "label": decision.action,
            "attributes": {
                "total_score": decision.total_score,
                "level": decision.level,
                "action": decision.action,
                "matched_rules": decision.matched_rules,
                "hard_blocks": decision.hard_blocks,
                "blocked_events": decision.blocked_events,
                "safe_outputs": decision.safe_outputs,
            },
        }
    )
    if previous_event_id:
        edges.append(
            {
                "id": "edge:last_event:decision",
                "type": "measured_by",
                "from": previous_event_id,
                "to": decision_node_id,
                "label": "最后一次工具调用进入风险计量",
            }
        )
    else:
        edges.append(
            {
                "id": "edge:task:decision",
                "type": "measured_by",
                "from": task_node_id,
                "to": decision_node_id,
                "label": "任务直接进入风险计量",
            }
        )

    for factor in decision.factors:
        factor_id = f"factor:{factor.code}"
        nodes.append(
            {
                "id": factor_id,
                "type": "risk_factor",
                "label": f"{factor.code}:{factor.name}",
                "attributes": {
                    "code": factor.code,
                    "name": factor.name,
                    "score": factor.score,
                    "evidence": factor.evidence,
                },
            }
        )
        edges.append(
            {
                "id": f"edge:factor:{factor.code}:decision",
                "type": "contributes_to",
                "from": factor_id,
                "to": decision_node_id,
                "label": "风险因子贡献最终决策",
                "weight": decision.scoring_details.get("weights", {}).get(factor.code),
            }
        )

    graph = {
        "version": "execution-graph-v1",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }
    graph["graph_hash"] = stable_hash(graph)
    return graph


def build_graph_data_flow_edges(event_node_ids: list[tuple[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    taint_sources = [
        (node_id, event)
        for node_id, event in event_node_ids
        if event.name in {"read_sensitive_file", "read_secret", "read_credential", "query_database"}
        or event.data_level in {"internal_sensitive", "secret", "confidential"}
    ]
    side_effects = [
        (node_id, event)
        for node_id, event in event_node_ids
        if event.name in {
            "write_file",
            "send_email",
            "upload_file",
            "run_shell",
            "apply_patch",
            "delete_file",
            "delete_audit_log",
            "modify_official_document",
            "submit_approval",
            "approve_request",
        }
    ]
    for source_index, (source_id, source_event) in enumerate(taint_sources, 1):
        for target_index, (target_id, target_event) in enumerate(side_effects, 1):
            if source_id == target_id:
                continue
            source_order = int(source_id.split(":", 2)[1])
            target_order = int(target_id.split(":", 2)[1])
            if target_order <= source_order:
                continue
            edges.append(
                {
                    "id": f"edge:data_flow:{source_index}:{target_index}",
                    "type": "tainted_data_flow",
                    "from": source_id,
                    "to": target_id,
                    "label": "前序内部/敏感数据可能流向后续副作用动作",
                    "risk": graph_data_flow_risk(target_event),
                }
            )
    return edges


def graph_event_risk_role(event: Any) -> str:
    text = f"{event.name} {event.params} {event.evidence}".lower().replace("\\", "/")
    if event.name in {"read_sensitive_file", "read_secret", "read_credential", "query_database"}:
        return "taint_source"
    if event.name in {"write_file", "apply_patch", "run_shell"} and any(
        marker in text for marker in ["outbox", "export", "exports", "tmp", "temp", "upload", "uploads", "queue"]
    ):
        return "staging_node"
    if event.name in {"send_email", "upload_file"}:
        return "external_sink"
    if event.name in {"modify_official_document", "submit_approval", "approve_request"}:
        return "official_mutation"
    if event.name in {"delete_file", "delete_audit_log"} or any(marker in text for marker in ["audit.log", "删除", "清空"]):
        return "destructive_or_audit_side_effect"
    return "normal"


def graph_event_target(event: Any) -> str:
    for key in ("path", "file", "target", "to", "url", "destination", "attachment"):
        value = event.params.get(key)
        if value:
            return str(value).replace("\\", "/")
    command = str(event.params.get("command", ""))
    if ">" in command:
        return command.split(">", 1)[1].strip().strip("\"' ")
    return ""


def graph_data_flow_risk(event: Any) -> str:
    role = graph_event_risk_role(event)
    if role == "external_sink":
        return "sensitive_data_external_transfer"
    if role == "staging_node":
        return "sensitive_data_staged"
    if role == "official_mutation":
        return "sensitive_context_affects_official_mutation"
    if role == "destructive_or_audit_side_effect":
        return "tainted_context_before_destructive_side_effect"
    return "tainted_context_before_side_effect"


def stable_hash(payload: Any) -> str:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:24]


def save_report(report: dict[str, Any], out_dir: str | Path) -> Path:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    task_id = report["task"]["task_id"]
    file_path = out_path / f"{task_id}_audit_report.json"
    file_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return file_path
