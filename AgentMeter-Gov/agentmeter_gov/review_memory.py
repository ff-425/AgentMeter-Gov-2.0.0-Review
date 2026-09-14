from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .intent_analyzer import analyze_intent, classify_tool_action
from .schema import TaskCase, ToolEvent


MEMORY_PATH = Path(__file__).resolve().parents[1] / "data" / "review_memory.json"
MEMORY_VERSION = "review-memory-v1"
APPROVED_SCORE_DELTA = 0
REJECTED_SCORE_DELTA = 20
APPROVED_REVIEW_MAX_SCORE = 55


@dataclass
class ReviewMemoryAdjustment:
    score_delta: int
    suppress_review: bool
    matched_memory_ids: list[str]
    reasons: list[str]
    decision: str
    guardrail_notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_review_memory(
    case: TaskCase,
    *,
    base_score: int,
    hard_blocks: list[str],
    review_required: list[str],
) -> ReviewMemoryAdjustment:
    current = case.events[-1] if case.events else None
    if current is None:
        return _empty_adjustment("none")

    memories = _active_memories(load_review_memory().get("memories", []))
    if not memories:
        return _empty_adjustment("none")

    guardrails = _guardrail_notes(case, current)
    matched_rejections = [
        memory for memory in memories
        if memory.get("decision") == "rejected" and _matches_memory(memory, case, current)
    ]
    if matched_rejections:
        ids = [str(item.get("memory_id", "")) for item in matched_rejections if item.get("memory_id")]
        return ReviewMemoryAdjustment(
            score_delta=REJECTED_SCORE_DELTA,
            suppress_review=False,
            matched_memory_ids=ids,
            reasons=[
                "similar action was rejected before; increase risk and keep stronger control",
            ],
            decision="rejected_memory_matched",
            guardrail_notes=guardrails,
        )

    matched_approvals = [
        memory for memory in memories
        if memory.get("decision") == "approved" and _matches_memory(memory, case, current)
    ]
    if not matched_approvals:
        return _empty_adjustment("none", guardrails)

    ids = [str(item.get("memory_id", "")) for item in matched_approvals if item.get("memory_id")]
    can_reduce_review = (
        not hard_blocks
        and bool(review_required)
        and base_score <= _approved_risk_max(matched_approvals)
        and not _is_hard_risk_context(case, current)
    )
    if can_reduce_review:
        return ReviewMemoryAdjustment(
            score_delta=APPROVED_SCORE_DELTA,
            suppress_review=False,
            matched_memory_ids=ids,
            reasons=[
                "bounded approved-review memory matched; keep per-action review and use memory only as audit context",
            ],
            decision="approved_memory_matched_no_auto_release",
            guardrail_notes=guardrails,
        )

    return ReviewMemoryAdjustment(
        score_delta=0,
        suppress_review=False,
        matched_memory_ids=ids,
        reasons=[
            "approved memory matched but guardrails prevent automatic review suppression",
        ],
        decision="approved_memory_guarded",
        guardrail_notes=guardrails,
    )


def build_memory_record(
    *,
    decision: str,
    user_id: str,
    review_id: str,
    source: str,
    proposed_tool_call: dict[str, Any],
    risk_score: int,
    matched_rules: list[str] | None = None,
    expires_at: str = "",
    max_uses: int = 2,
) -> dict[str, Any]:
    event = ToolEvent(
        name=str(proposed_tool_call.get("name", "unknown")),
        params=dict(proposed_tool_call.get("params", {}) or {}),
        source=str(proposed_tool_call.get("source", source)),
        data_level=str(proposed_tool_call.get("data_level", "public")),
        result=str(proposed_tool_call.get("result", "reviewed")),
        evidence=str(proposed_tool_call.get("evidence", "")),
    )
    now = datetime.now(timezone.utc).isoformat()
    return {
        "memory_id": f"RM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{review_id or 'MANUAL'}",
        "version": MEMORY_VERSION,
        "decision": decision,
        "user_id": user_id or "openclaw_user",
        "intent": "unknown",
        "tool_action": classify_tool_action(event),
        "tool_name": event.name,
        "source_data_level": event.data_level,
        "target_path_prefix": _target_prefix(event),
        "external_target": _has_external_target(event),
        "target_key": _target_key(event),
        "approved_risk_max": APPROVED_REVIEW_MAX_SCORE if decision == "approved" else 0,
        "score_delta": APPROVED_SCORE_DELTA if decision == "approved" else REJECTED_SCORE_DELTA,
        "max_uses": min(max_uses, 1) if decision == "approved" else 0,
        "used_count": 0,
        "expires_at": expires_at,
        "created_at": now,
        "created_from_review_id": review_id,
        "source": source,
        "risk_score": int(risk_score or 0),
        "matched_rules": matched_rules or [],
        "status": "active",
    }


def load_review_memory() -> dict[str, Any]:
    if not MEMORY_PATH.exists():
        return {"version": MEMORY_VERSION, "memories": []}
    try:
        data = json.loads(MEMORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": MEMORY_VERSION, "memories": []}
    if isinstance(data, dict):
        data.setdefault("version", MEMORY_VERSION)
        data.setdefault("memories", [])
        return data
    return {"version": MEMORY_VERSION, "memories": []}


def save_review_memory(data: dict[str, Any]) -> None:
    MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    MEMORY_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _empty_adjustment(decision: str, guardrails: list[str] | None = None) -> ReviewMemoryAdjustment:
    return ReviewMemoryAdjustment(
        score_delta=0,
        suppress_review=False,
        matched_memory_ids=[],
        reasons=[],
        decision=decision,
        guardrail_notes=guardrails or [],
    )


def _active_memories(memories: Any) -> list[dict[str, Any]]:
    if not isinstance(memories, list):
        return []
    now = datetime.now(timezone.utc)
    active: list[dict[str, Any]] = []
    for memory in memories:
        if not isinstance(memory, dict) or memory.get("status", "active") != "active":
            continue
        expires_at = str(memory.get("expires_at", "") or "")
        if expires_at:
            try:
                expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except ValueError:
                expires = None
            if expires and expires < now:
                continue
        max_uses = int(memory.get("max_uses", 0) or 0)
        used_count = int(memory.get("used_count", 0) or 0)
        if memory.get("decision") == "approved" and max_uses > 0 and used_count >= max_uses:
            continue
        active.append(memory)
    return active


def _matches_memory(memory: dict[str, Any], case: TaskCase, event: ToolEvent) -> bool:
    memory_user = str(memory.get("user_id", "") or "")
    if memory_user and memory_user not in {"anonymous", case.user_id}:
        return False
    if memory.get("tool_action") and memory.get("tool_action") != classify_tool_action(event):
        return False
    if memory.get("source_data_level") and memory.get("source_data_level") != event.data_level:
        return False
    if bool(memory.get("external_target", False)) != _has_external_target(event):
        return False
    target_prefix = str(memory.get("target_path_prefix", "") or "")
    if target_prefix and not _target_key(event).startswith(target_prefix):
        return False
    return True


def _approved_risk_max(memories: list[dict[str, Any]]) -> int:
    values = [int(item.get("approved_risk_max", APPROVED_REVIEW_MAX_SCORE) or APPROVED_REVIEW_MAX_SCORE) for item in memories]
    return max(values) if values else APPROVED_REVIEW_MAX_SCORE


def _is_hard_risk_context(case: TaskCase, event: ToolEvent) -> bool:
    text = f"{case.user_goal} {event.name} {json.dumps(event.params, ensure_ascii=False)}".lower()
    hard_markers = [
        ".env",
        ".npmrc",
        "token",
        "api_key",
        "password",
        "secret",
        "disable-agentmeter",
        "disable guard",
        "关闭防护",
        "删除日志",
        "清空日志",
        "audit.log",
        "remove-item",
        "external-demo",
        "http://",
        "https://",
    ]
    official_tamper = any(marker in text for marker in ["pay immediately", "becomes approved", "改为通过", "修改合同", "替换付款"])
    return official_tamper or any(marker in text for marker in hard_markers)


def _guardrail_notes(case: TaskCase, event: ToolEvent) -> list[str]:
    notes: list[str] = []
    if _is_hard_risk_context(case, event):
        notes.append("hard-risk context cannot be auto-released by memory")
    if _has_external_target(event):
        notes.append("external target requires stronger review boundary")
    return notes


def _consume_approval_memory(memory_ids: list[str]) -> None:
    if not memory_ids:
        return
    data = load_review_memory()
    changed = False
    for memory in data.get("memories", []):
        if isinstance(memory, dict) and memory.get("memory_id") in memory_ids:
            memory["used_count"] = int(memory.get("used_count", 0) or 0) + 1
            memory["last_used_at"] = datetime.now(timezone.utc).isoformat()
            changed = True
    if changed:
        save_review_memory(data)


def _target_key(event: ToolEvent) -> str:
    target = str(
        event.params.get("path")
        or event.params.get("target")
        or event.params.get("file")
        or event.params.get("destination")
        or event.params.get("to")
        or _extract_shell_destination(str(event.params.get("command", "")))
        or ""
    ).replace("\\", "/")
    return _normalize_target_key(target)


def _target_prefix(event: ToolEvent) -> str:
    target = _target_key(event)
    parts = [part for part in target.split("/") if part]
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}/"
    if parts:
        return f"{parts[0]}/"
    return ""


def _has_external_target(event: ToolEvent) -> bool:
    text = json.dumps(event.params, ensure_ascii=False).lower()
    return any(marker in text for marker in ["http://", "https://", "@external", "external-demo", "send_to_external"])


def _extract_shell_destination(command: str) -> str:
    if not command:
        return ""
    copy_match = re.search(r"copy-item\s+['\"][^'\"]+['\"]\s+['\"]([^'\"]+)['\"]", command, flags=re.I)
    if copy_match:
        return copy_match.group(1)
    dest_match = re.search(r"-Destination\s+['\"]?([^'\";\r\n]+)", command, flags=re.I)
    if dest_match:
        return dest_match.group(1).strip()
    copy_unquoted = re.search(r"copy-item\s+\S+\s+([^\s;|]+)(?:\s|;|\||$)", command, flags=re.I)
    if copy_unquoted:
        return copy_unquoted.group(1).strip()
    return ""


def _normalize_target_key(target: str) -> str:
    normalized = target.replace("\\", "/").strip().lstrip("/")
    lowered = normalized.lower()
    workspace_marker = ".openclaw/workspace/"
    marker_index = lowered.find(workspace_marker)
    if marker_index >= 0:
        normalized = normalized[marker_index + len(workspace_marker):]
        lowered = normalized.lower()
    demo_index = lowered.find("agentmeter_demo/")
    if demo_index >= 0:
        normalized = normalized[demo_index:]
    return normalized.lstrip("/")
