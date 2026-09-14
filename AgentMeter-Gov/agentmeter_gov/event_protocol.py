from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = "agentmeter.event.v1"
REQUIRED_FIELDS = {"schema_version", "adapter", "event_type", "timestamp"}
TOOL_PROPOSAL_TYPES = {"tool_proposal", "tool_call_proposed"}


def normalize_event(payload: dict[str, Any], adapter: str = "generic") -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TypeError("event payload must be an object")
    event = dict(payload)
    event.setdefault("schema_version", SCHEMA_VERSION)
    event.setdefault("adapter", adapter)
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    event.setdefault("event_type", "runtime_event")
    event.setdefault("audit_id", event.get("task_id", ""))
    event.setdefault("protocol_stage", protocol_stage(event["event_type"]))
    if not event.get("event_id"):
        canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        event["event_id"] = f"AME-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:20]}"
    validate_event(event)
    return event


def validate_event(event: dict[str, Any]) -> None:
    validate_event_structure(event)
    missing = sorted(field for field in REQUIRED_FIELDS if not event.get(field))
    if missing:
        raise ValueError(f"missing event fields: {', '.join(missing)}")
    if event["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported schema_version")


def validate_event_structure(event: dict[str, Any]) -> None:
    """Check fields consumed by monitoring without rejecting legacy envelopes.

    Missing optional fields and null containers remain supported. Evidence and
    tool parameter values are intentionally free-form; only their containers
    and the identifiers/status fields used for grouping have a fixed shape.
    Error messages contain field names, never submitted values.
    """
    if not isinstance(event, dict):
        raise TypeError("event payload must be an object")
    # Reject non-finite values anywhere in the envelope: JSON browser clients
    # cannot parse NaN/Infinity even inside otherwise free-form tool parameters.
    try:
        json.dumps(event, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise ValueError("event must contain valid finite JSON values") from None

    def expect(mapping, key, kind, path=""):
        value = mapping.get(key)
        if value is not None and not isinstance(value, kind):
            name = "object" if kind is dict else "array" if kind is list else "string"
            raise ValueError(f"{path}{key} must be an {name}" if name[0] in "aeiou" else f"{path}{key} must be a {name}")

    for field in (
        "schema_version", "adapter", "event_type", "timestamp", "event_id",
        "task_id", "session_key", "run_id", "audit_id", "parent_audit_id",
        "tool_name", "gate_action", "decision", "action", "status",
        "execution_result", "approval_id", "review_id", "review_decision",
        "approval_scope", "call_id", "tool_call_id", "operation_id",
    ):
        expect(event, field, str)
    timestamp = event.get("timestamp")
    if timestamp:
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("timestamp must be an ISO 8601 datetime") from None
    score = event.get("risk_score")
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score)):
        raise ValueError("risk_score must be a finite number")
    for field in (
        "proposed_tool_call", "parameters", "security_control", "scoring_details",
        "factor_contributions", "threshold_explanation", "recovery_plan", "recovery_execution",
    ):
        expect(event, field, dict)
    for field in ("triggered_rules", "findings", "inherited_authorization"):
        expect(event, field, list)
    proposed = event.get("proposed_tool_call") or {}
    expect(proposed, "params", dict, "proposed_tool_call.")
    expect(proposed, "name", str, "proposed_tool_call.")
    for container in ("security_control", "scoring_details"):
        details = event.get(container) or {}
        for field in ("factor_contributions", "threshold_explanation", "recovery_plan", "recovery_execution", "taint_summary", "batch_analysis"):
            expect(details, field, dict, container + ".")
        if container == "security_control":
            expect(details, "controls", list, container + ".")


def protocol_stage(event_type: str) -> str:
    return {
        "input_event": "input",
        "risk_decision_event": "decision",
        "tool_event": "tool_result",
        "output_guard_event": "output",
        "output_postflight_event": "output",
        "memory_governance_event": "memory",
        "subagent_event": "delegation",
        "result_event": "result",
        "supply_chain_scan_event": "supply_chain",
        "tool_proposal": "decision",
        "tool_call_proposed": "decision",
    }.get(str(event_type), "runtime")


def normalize_gate_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate a runtime-neutral event envelope into the internal gate request."""
    if not isinstance(payload, dict):
        raise TypeError("gate payload must be an object")
    if "proposed_tool_call" in payload:
        request = dict(payload)
        request.setdefault("schema_version", SCHEMA_VERSION)
        request.setdefault("adapter", "legacy")
        return request

    event = normalize_event(payload, adapter=str(payload.get("adapter") or "generic"))
    if event["event_type"] not in TOOL_PROPOSAL_TYPES:
        raise ValueError(f"unsupported gate event_type: {event['event_type']}")
    operation = event.get("operation")
    if not isinstance(operation, dict) or not (operation.get("name") or operation.get("operation")):
        raise ValueError("tool proposal requires operation.name")
    task = event.get("task") if isinstance(event.get("task"), dict) else {}
    context = event.get("context") if isinstance(event.get("context"), dict) else {}
    history = event.get("history", context.get("history", []))
    if not isinstance(history, list):
        raise ValueError("tool proposal history must be an array")
    input_sources = event.get("input_sources", context.get("input_sources", []))
    if not isinstance(input_sources, list):
        raise ValueError("tool proposal input_sources must be an array")
    return {
        "schema_version": SCHEMA_VERSION,
        "adapter": event["adapter"],
        "event_id": event["event_id"],
        "audit_id": event.get("audit_id", ""),
        "task_id": event.get("task_id") or task.get("id") or event.get("audit_id") or "live-agent-task",
        "title": event.get("title") or task.get("title") or "Agent runtime tool-call gate",
        "user_id": event.get("user_id") or task.get("user_id") or "agent_user",
        "session_key": event.get("session_key") or context.get("session_key") or "",
        "user_goal": event.get("goal") or task.get("goal") or "",
        "input_sources": input_sources,
        "history_events": [_normalize_operation(item, "history") for item in history],
        "proposed_tool_call": _normalize_operation(operation, "before_tool_call"),
    }


def _normalize_operation(item: Any, default_source: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("operation must be an object")
    name = item.get("name") or item.get("operation")
    if not name:
        raise ValueError("operation.name is required")
    params = item.get("params", item.get("parameters", {}))
    if not isinstance(params, dict):
        raise ValueError("operation parameters must be an object")
    return {
        "name": str(name),
        "params": params,
        "source": str(item.get("source") or default_source),
        "data_level": str(item.get("data_level") or item.get("data_classification") or "public"),
        "result": str(item.get("result") or item.get("status") or "proposed"),
        "evidence": str(item.get("evidence") or "standard event protocol operation"),
    }
