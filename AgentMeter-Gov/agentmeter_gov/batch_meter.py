from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .schema import TaskCase, ToolEvent


BATCH_PROFILE_PATH = Path(
    os.environ.get(
        "AGENTMETER_BATCH_PROFILE_PATH",
        str(Path(__file__).resolve().parents[1] / "data" / "batch_behavior_profile.json"),
    )
)
BATCH_PROFILE_VERSION = "batch-profile-v1"
LONG_WINDOW_DAYS = 7
SIDE_EFFECT_EVENTS = {
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
    "execute_payment",
    "grant_access",
}
EXTERNAL_EVENTS = {"send_email", "upload_file", "execute_payment", "grant_access"}
OFFICIAL_EVENTS = {"modify_official_document", "submit_approval", "approve_request"}
DESTRUCTIVE_EVENTS = {"delete_file", "delete_audit_log"}
STAGING_MARKERS = ("outbox", "export", "exports", "tmp", "temp", "upload", "uploads", "queue", "staged")
SENSITIVE_LEVELS = {"internal_sensitive", "secret", "confidential"}
EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)


@dataclass
class BatchBehaviorAnalysis:
    version: str
    side_effect_count: int
    write_count: int
    external_count: int
    destructive_count: int
    official_mutation_count: int
    affected_record_count: int
    business_state_change_count: int
    critical_state_change_count: int
    unique_target_count: int
    unique_email_target_count: int
    staging_write_count: int
    long_window_side_effect_count: int
    long_window_unique_target_count: int
    long_window_external_count: int
    sensitive_read_seen: bool
    split_operation_suspected: bool
    factor_boosts: dict[str, int]
    review_required: list[str]
    hard_blocks: list[str]
    triggered_rules: list[dict[str, Any]]
    target_summary: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_batch_behavior(case: TaskCase) -> BatchBehaviorAnalysis:
    events = case.events
    profile_events = _recent_profile_events(load_batch_profile(), case.user_id)
    side_effects = [event for event in events if event.name in SIDE_EFFECT_EVENTS]
    writes = [event for event in events if event.name in {"write_file", "apply_patch", "run_shell"} and _looks_like_write(event)]
    externals = [event for event in events if event.name in EXTERNAL_EVENTS or _has_external_target(event)]
    destructives = [event for event in events if event.name in DESTRUCTIVE_EVENTS or _looks_destructive(event)]
    official_mutations = [event for event in events if event.name in OFFICIAL_EVENTS or _looks_official_mutation(event)]
    affected_record_count = sum(_event_affected_record_count(event) for event in side_effects)
    business_state_changes = [event for event in side_effects if _is_business_state_change(event)]
    critical_state_changes = [event for event in business_state_changes if _is_critical_business_state_change(event)]
    staging_writes = [event for event in writes if _is_staging_target(event)]
    sensitive_read_seen = any(
        event.name in {"read_sensitive_file", "read_secret", "read_credential", "query_database"}
        or event.data_level in SENSITIVE_LEVELS
        for event in events
    )

    targets = sorted({target for event in side_effects for target in _event_targets(event) if target})
    email_targets = sorted({email.lower() for event in externals for email in EMAIL_RE.findall(_event_text(event))})
    split_operation_suspected = _split_operation_suspected(
        side_effects=side_effects,
        writes=writes,
        externals=externals,
        staging_writes=staging_writes,
        sensitive_read_seen=sensitive_read_seen,
        target_count=len(targets),
    )
    burst_marker = _side_effect_burst_marker(events[-1] if events else None)
    long_window_targets = sorted({
        str(item.get("target_key", ""))
        for item in profile_events
        if item.get("target_key")
    })
    long_window_side_effect_count = len(profile_events)
    long_window_unique_target_count = len(long_window_targets)
    long_window_external_count = sum(1 for item in profile_events if item.get("external_target"))
    current_event = events[-1] if events else None
    long_window_applicable = _long_window_applicable(
        current_event=current_event,
        externals=externals,
        destructives=destructives,
        official_mutations=official_mutations,
        staging_writes=staging_writes,
        sensitive_read_seen=sensitive_read_seen,
        burst_marker=burst_marker,
    )

    triggered_rules: list[dict[str, Any]] = []
    review_required: list[str] = []
    hard_blocks: list[str] = []
    factor_boosts = {"P": 0, "T": 0, "A": 0}

    def add_rule(code: str, action: str, factors: list[str], reason: str, severity: int) -> None:
        triggered_rules.append(
            {
                "code": code,
                "action": action,
                "factors": factors,
                "severity": severity,
                "reason": reason,
            }
        )
        for factor in factors:
            factor_boosts[factor] = max(factor_boosts.get(factor, 0), severity)

    if len(side_effects) >= 4:
        add_rule("BATCH-02", "human_review", ["P", "T"], "同一任务链出现多次副作用动作", 72)
        review_required.append("repeated side effects in one OpenClaw task require owner review")
    if business_state_changes:
        add_rule(
            "GOV-BIZ-STATE-01",
            "human_review",
            ["P", "A"],
            "internal business-state mutation requires verified authorization scope",
            64,
        )
        review_required.append("internal business-state change requires verified authorization scope")
    if affected_record_count >= 2:
        add_rule(
            "GOV-BATCH-RECORD-01",
            "human_review",
            ["P", "T", "A"],
            "one tool call mutates multiple business records",
            72,
        )
        review_required.append("multi-record mutation requires owner confirmation")
    if critical_state_changes:
        add_rule(
            "GOV-BIZ-STATE-CRITICAL-01",
            "human_review",
            ["P", "T", "A"],
            "business records are entering a critical terminal state",
            74,
        )
        review_required.append("critical terminal-state change requires owner confirmation")
    if burst_marker and int(burst_marker.get("distinct_targets", 0) or 0) >= 5:
        add_rule("BATCH-02", "human_review", ["P", "T"], "插件检测到短时间多目标副作用动作", 72)
        review_required.append("side-effect burst marker requires batch-impact review")
    if len(targets) >= 4:
        add_rule("BATCH-03", "human_review", ["P", "T"], "同一任务影响多个不同对象，存在批量操作风险", 76)
        review_required.append("many distinct targets in one task require batch-impact review")
    if len(email_targets) >= 3:
        add_rule("BATCH-04", "human_review", ["P", "T"], "短链路内出现多个邮件目标，疑似拆分群发", 82)
        review_required.append("multiple email targets require recipient-list review")
    if sensitive_read_seen and len(staging_writes) >= 2:
        add_rule("BATCH-05", "human_review", ["T", "A"], "敏感读取后多次写入中转区，疑似分批中转", 86)
        review_required.append("sensitive data staged through repeated writes requires quarantine review")
    if sensitive_read_seen and len(staging_writes) >= 2 and externals:
        add_rule("BATCH-06", "block", ["T", "P", "A"], "敏感中转后出现外发/上传，形成拆分外发链", 95)
        hard_blocks.append("split sensitive staging followed by external transfer must be blocked")
    if len(official_mutations) >= 2:
        add_rule("BATCH-07", "block", ["P", "T", "A"], "连续修改多个审批、合同或验收对象", 92)
        hard_blocks.append("repeated official-document mutations must be blocked")
    if len(destructives) >= 2:
        add_rule("BATCH-08", "block", ["P", "T", "A"], "连续删除或覆盖多个对象，存在破坏性批量操作", 95)
        hard_blocks.append("repeated destructive operations must be blocked")
    if long_window_applicable and (long_window_side_effect_count >= 30 or long_window_unique_target_count >= 20):
        add_rule("BATCH-09", "human_review", ["P", "T"], "跨会话长期窗口内副作用或目标数量异常偏高", 78)
        review_required.append("long-window repeated side effects require batch-impact review")
    if long_window_applicable and long_window_external_count >= 5:
        add_rule("BATCH-10", "human_review", ["P", "T"], "跨会话长期窗口内外发/上传次数异常偏高", 84)
        review_required.append("long-window repeated external transfers require owner review")

    return BatchBehaviorAnalysis(
        version="batch-meter-v1",
        side_effect_count=len(side_effects),
        write_count=len(writes),
        external_count=len(externals),
        destructive_count=len(destructives),
        official_mutation_count=len(official_mutations),
        affected_record_count=affected_record_count,
        business_state_change_count=len(business_state_changes),
        critical_state_change_count=len(critical_state_changes),
        unique_target_count=len(targets),
        unique_email_target_count=len(email_targets),
        staging_write_count=len(staging_writes),
        long_window_side_effect_count=long_window_side_effect_count,
        long_window_unique_target_count=long_window_unique_target_count,
        long_window_external_count=long_window_external_count,
        sensitive_read_seen=sensitive_read_seen,
        split_operation_suspected=split_operation_suspected or bool(burst_marker),
        factor_boosts=factor_boosts,
        review_required=review_required,
        hard_blocks=hard_blocks,
        triggered_rules=triggered_rules,
        target_summary={
            "targets": targets[:20],
            "email_targets": email_targets[:20],
            "staging_targets": [_event_primary_target(event) for event in staging_writes[:20]],
            "side_effect_burst": [burst_marker] if burst_marker else [],
            "long_window_targets": long_window_targets[:20],
            "business_state_transitions": [
                transition
                for event in business_state_changes[:20]
                for transition in _edit_semantics(event).get("transitions", [])[:20]
            ],
        },
    )


def record_batch_observation(case: TaskCase, gate_action: str) -> dict[str, Any]:
    current = case.events[-1] if case.events else None
    if gate_action != "allow":
        return {"recorded": False, "reason": "action not released; do not learn from blocked or pending side effects"}
    if current is None or current.name not in SIDE_EFFECT_EVENTS:
        return {"recorded": False, "reason": "no side-effect event"}

    data = load_batch_profile()
    now = datetime.now(timezone.utc)
    events = _active_profile_events(data.get("events", []), now)
    item = {
        "event_id": _event_id(case, current),
        "created_at": now.isoformat(),
        "user_id": case.user_id,
        "task_id": case.task_id,
        "tool_name": current.name,
        "action_family": _action_family(current),
        "target_key": _event_primary_target(current),
        "external_target": _has_external_target(current),
        "data_level": current.data_level,
        "affected_record_count": _event_affected_record_count(current),
        "business_state_change": _is_business_state_change(current),
        "gate_action": gate_action,
        "result": current.result,
    }
    deduped = [event for event in events if event.get("event_id") != item["event_id"]]
    deduped.append(item)
    data = {
        "version": BATCH_PROFILE_VERSION,
        "updated_at": now.isoformat(),
        "window_days": LONG_WINDOW_DAYS,
        "events": deduped[-2000:],
    }
    save_batch_profile(data)
    return {"recorded": True, "event_id": item["event_id"], "window_event_count": len(data["events"])}


def load_batch_profile() -> dict[str, Any]:
    if not BATCH_PROFILE_PATH.exists():
        return {"version": BATCH_PROFILE_VERSION, "events": []}
    try:
        data = json.loads(BATCH_PROFILE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": BATCH_PROFILE_VERSION, "events": []}
    if not isinstance(data, dict):
        return {"version": BATCH_PROFILE_VERSION, "events": []}
    data.setdefault("version", BATCH_PROFILE_VERSION)
    data.setdefault("events", [])
    return data


def save_batch_profile(data: dict[str, Any]) -> None:
    BATCH_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BATCH_PROFILE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _recent_profile_events(data: dict[str, Any], user_id: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    active = _active_profile_events(data.get("events", []), now)
    return [
        item for item in active
        if str(item.get("user_id", "")) in {"", "anonymous", str(user_id)}
        and str(item.get("gate_action", "")) == "allow"
    ]


def _long_window_applicable(
    *,
    current_event: ToolEvent | None,
    externals: list[ToolEvent],
    destructives: list[ToolEvent],
    official_mutations: list[ToolEvent],
    staging_writes: list[ToolEvent],
    sensitive_read_seen: bool,
    burst_marker: dict[str, Any] | None,
) -> bool:
    if current_event is None:
        return False
    if _is_low_impact_event(current_event):
        return False
    if externals or destructives or official_mutations or staging_writes or sensitive_read_seen or burst_marker:
        return True
    if current_event.data_level in SENSITIVE_LEVELS:
        return True
    return False


def _is_low_impact_event(event: ToolEvent) -> bool:
    text = _event_text(event).lower()
    if event.name in {"read_file", "read_document", "search_memory", "web_search", "web_fetch"} and event.data_level == "public":
        return True
    if event.name != "run_shell":
        return False
    write_markers = (
        "out-file",
        "set-content",
        "add-content",
        "new-item",
        "mkdir",
        "remove-item",
        "del ",
        " rm ",
        "curl ",
        "iwr ",
        "wget ",
    )
    if any(marker in text for marker in write_markers):
        return False
    read_markers = (
        "get-content",
        "get-childitem",
        "test-path",
        "select-object",
        "format-table",
        " dir ",
        "ls ",
        "python --version",
        "node --version",
        "npm --version",
        "--help",
    )
    return any(marker in text for marker in read_markers)


def _active_profile_events(events: Any, now: datetime) -> list[dict[str, Any]]:
    if not isinstance(events, list):
        return []
    cutoff = now - timedelta(days=LONG_WINDOW_DAYS)
    active: list[dict[str, Any]] = []
    for item in events:
        if not isinstance(item, dict):
            continue
        try:
            created = datetime.fromisoformat(str(item.get("created_at", "")).replace("Z", "+00:00"))
        except ValueError:
            continue
        if created >= cutoff:
            active.append(item)
    return active


def _split_operation_suspected(
    *,
    side_effects: list[ToolEvent],
    writes: list[ToolEvent],
    externals: list[ToolEvent],
    staging_writes: list[ToolEvent],
    sensitive_read_seen: bool,
    target_count: int,
) -> bool:
    if sensitive_read_seen and (len(staging_writes) >= 2 or externals):
        return True
    if len(side_effects) >= 6 and target_count >= 4:
        return True
    if len(writes) >= 5 and target_count >= 4:
        return True
    return False


def _event_text(event: ToolEvent) -> str:
    return f"{event.name} {event.params} {event.evidence}".lower().replace("\\", "/")


def _event_targets(event: ToolEvent) -> list[str]:
    values: list[str] = []
    for key in ("path", "file", "target", "to", "url", "destination", "attachment"):
        value = event.params.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value:
            values.append(str(value))
    shell_destination = _extract_shell_destination(str(event.params.get("command", "")))
    if shell_destination:
        values.append(shell_destination)
    return [_normalize_target(value) for value in values if str(value).strip()]


def _event_primary_target(event: ToolEvent) -> str:
    targets = _event_targets(event)
    return targets[0] if targets else ""


def _normalize_target(value: str) -> str:
    text = str(value).replace("\\", "/").strip().lower()
    marker = "agentmeter_demo/"
    if marker in text:
        text = text[text.index(marker) :]
    return text.strip("\"' ")


def _looks_like_write(event: ToolEvent) -> bool:
    if event.name in {"write_file", "apply_patch"}:
        return True
    if event.name != "run_shell":
        return False
    text = _event_text(event)
    return any(marker in text for marker in ["set-content", "add-content", "out-file", "copy-item", "new-item", ">", ">>"])


def _looks_destructive(event: ToolEvent) -> bool:
    text = _event_text(event)
    return any(marker in text for marker in ["remove-item", "clear-content", " del ", " rm ", "erase ", "delete", "删除", "清空", "覆盖"])


def _looks_official_mutation(event: ToolEvent) -> bool:
    text = _event_text(event)
    official = any(marker in text for marker in ["审批", "验收", "合同", "公文", "approval", "contract"])
    mutation = any(marker in text for marker in ["修改", "改为", "改成", "replace", "newtext", "approved", "submit"])
    return official and mutation


def _is_staging_target(event: ToolEvent) -> bool:
    # Staging is a property of the destination, not of words appearing in a
    # file body (for example, "do not upload").
    target = _event_primary_target(event)
    return any(marker in target for marker in STAGING_MARKERS)


def _has_external_target(event: ToolEvent) -> bool:
    if event.name in EXTERNAL_EVENTS:
        return True
    explicit_values: list[str] = []
    for key in ("to", "url", "recipient", "recipients", "endpoint", "webhook", "upload_url"):
        value = event.params.get(key)
        if isinstance(value, list):
            explicit_values.extend(str(item) for item in value)
        elif value:
            explicit_values.append(str(value))
    explicit = " ".join(explicit_values).lower()
    if EMAIL_RE.search(explicit) or any(marker in explicit for marker in ["http://", "https://", "ftp://", "s3://"]):
        return True
    if any(marker in explicit for marker in ["external", "outside", "partner", "外部", "外发"]):
        return True

    # File content may mention an address or explicitly say that nothing is
    # sent. Content is not a transfer target. A shell command, however, can
    # carry an implicit network destination and remains part of this check.
    command = str(event.params.get("command", "")).lower()
    if event.name == "run_shell" and (
        EMAIL_RE.search(command)
        or any(marker in command for marker in ["http://", "https://", "ftp://", "s3://"])
    ):
        return True
    return False


def _extract_shell_destination(command: str) -> str:
    text = str(command or "")
    explicit = re.search(r"(?:-Destination|-Path)\s+[\"']?([^\"';\r\n]+)[\"']?", text, flags=re.IGNORECASE)
    if explicit:
        return explicit.group(1)
    redirect = re.search(r">>?\s*[\"']?([^\"';\r\n]+)[\"']?", text)
    if redirect:
        return redirect.group(1)
    return ""


def _side_effect_burst_marker(event: ToolEvent | None) -> dict[str, Any] | None:
    if event is None:
        return None
    marker = event.params.get("agentmeter_side_effect_burst")
    if isinstance(marker, dict):
        return marker
    return None


def _edit_semantics(event: ToolEvent) -> dict[str, Any]:
    value = event.params.get("agentmeter_edit_semantics")
    return value if isinstance(value, dict) else {}


def _event_affected_record_count(event: ToolEvent) -> int:
    semantics = _edit_semantics(event)
    candidates = [semantics.get("affected_records")]
    candidates.extend(
        event.params.get(key)
        for key in ("affected_records", "affected_rows", "row_count", "record_count", "modified_count")
    )
    edits = event.params.get("edits")
    if isinstance(edits, list):
        candidates.append(len(edits))
    counts: list[int] = []
    for value in candidates:
        try:
            counts.append(max(0, int(value)))
        except (TypeError, ValueError):
            continue
    if counts:
        return max(counts)
    return 1 if semantics or isinstance(edits, list) else 0


def _is_business_state_change(event: ToolEvent) -> bool:
    semantics = _edit_semantics(event)
    if semantics.get("business_state_change") is True:
        return True
    fields = semantics.get("fields", [])
    if isinstance(fields, list) and any(
        str(field).strip().lower() in {"status", "state", "workflow_status", "approval_status", "task_status"}
        for field in fields
    ):
        return True
    return False


def _is_critical_business_state_change(event: ToolEvent) -> bool:
    return _edit_semantics(event).get("critical_terminal_state") is True


def _action_family(event: ToolEvent) -> str:
    if event.name in {"send_email", "upload_file"} or _has_external_target(event):
        return "external_send"
    if event.name in {"delete_file", "delete_audit_log"} or _looks_destructive(event):
        return "destructive"
    if event.name in {"modify_official_document", "submit_approval", "approve_request"} or _looks_official_mutation(event):
        return "official_mutation"
    if event.name in {"write_file", "apply_patch", "run_shell"} and _looks_like_write(event):
        return "write"
    return event.name


def _event_id(case: TaskCase, event: ToolEvent) -> str:
    payload = json.dumps(
        {
            "task_id": case.task_id,
            "user_id": case.user_id,
            "name": event.name,
            "target": _event_primary_target(event),
            "params": event.params,
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
