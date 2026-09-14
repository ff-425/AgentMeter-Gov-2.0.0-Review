from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .intent_analyzer import IntentAnalysis, classify_tool_action
from .schema import RiskDecision, TaskCase, ToolEvent


PROFILE_PATH = Path(__file__).resolve().parents[1] / "data" / "user_profiles.json"
MIN_PROFILE_EVENTS = 10


@dataclass
class UserProfileAnalysis:
    user_id: str
    profile_confidence: float
    cold_start: bool
    behavior_anomaly_score: int
    anomaly_reasons: list[str]
    profile_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_user_profile(case: TaskCase, intent: IntentAnalysis) -> UserProfileAnalysis:
    user_id = case.user_id or "anonymous"
    profiles = load_profiles()
    profile = profiles.get(user_id, _empty_profile())
    total_events = int(profile.get("total_events", 0) or 0)
    confidence = profile_confidence(total_events)
    cold_start = total_events < MIN_PROFILE_EVENTS
    current_event = case.events[-1] if case.events else None

    if cold_start:
        return UserProfileAnalysis(
            user_id=user_id,
            profile_confidence=confidence,
            cold_start=True,
            behavior_anomaly_score=0,
            anomaly_reasons=["insufficient historical samples; user habit factor is not applied"],
            profile_summary=summarize_profile(profile),
        )

    points = 0
    reasons: list[str] = []
    observed_action = classify_tool_action(current_event)
    target_prefix = extract_target_prefix(current_event)

    if _rare(profile, "intent_counts", intent.intent_type):
        points += 2
        reasons.append(f"intent {intent.intent_type} is rare for this user profile")
    if _rare(profile, "tool_counts", observed_action):
        points += 2
        reasons.append(f"tool action {observed_action} is rare for this user profile")
    if target_prefix and _rare(profile, "target_prefix_counts", target_prefix):
        points += 2
        reasons.append(f"target prefix {target_prefix} is rare for this user profile")
    if is_external_action(current_event) and float(profile.get("external_send_rate", 0) or 0) < 0.08:
        points += 3
        reasons.append("external communication is uncommon for this user profile")

    batch_size = estimate_batch_size(current_event)
    avg_batch = float(profile.get("avg_batch_size", 1) or 1)
    if batch_size >= max(5, avg_batch * 3):
        points += 2
        reasons.append(f"batch size {batch_size} is much higher than user average {avg_batch:.1f}")

    if not reasons:
        reasons.append("current behavior is consistent with the user profile")

    return UserProfileAnalysis(
        user_id=user_id,
        profile_confidence=confidence,
        cold_start=False,
        behavior_anomaly_score=min(100, points * 10),
        anomaly_reasons=reasons,
        profile_summary=summarize_profile(profile),
    )


def update_user_profile(case: TaskCase, decision: RiskDecision) -> None:
    """Accumulate only accepted low/medium-risk behavior into the user baseline."""
    if decision.action != "allow":
        return
    if decision.hard_blocks or not case.events:
        return

    user_id = case.user_id or "anonymous"
    profiles = load_profiles()
    profile = profiles.get(user_id, _empty_profile())
    current_event = case.events[-1]
    intent_type = str(decision.scoring_details.get("intent_analysis", {}).get("intent_type", "unknown"))
    tool_action = classify_tool_action(current_event)
    target_prefix = extract_target_prefix(current_event) or "unknown"
    batch_size = estimate_batch_size(current_event)

    profile["total_events"] = int(profile.get("total_events", 0) or 0) + 1
    _inc(profile, "intent_counts", intent_type)
    _inc(profile, "tool_counts", tool_action)
    _inc(profile, "target_prefix_counts", target_prefix)
    _update_average(profile, "avg_risk_score", decision.total_score)
    _update_average(profile, "avg_batch_size", batch_size)
    external_count = int(profile.get("external_send_count", 0) or 0) + (1 if is_external_action(current_event) else 0)
    profile["external_send_count"] = external_count
    profile["external_send_rate"] = round(external_count / max(1, int(profile["total_events"])), 4)
    profile["last_updated"] = datetime.now(timezone.utc).isoformat()
    profiles[user_id] = profile
    save_profiles(profiles)


def load_profiles() -> dict[str, dict[str, Any]]:
    try:
        if PROFILE_PATH.exists():
            data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {str(key): dict(value) for key, value in data.items() if isinstance(value, dict)}
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def save_profiles(profiles: dict[str, dict[str, Any]]) -> None:
    PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROFILE_PATH.write_text(json.dumps(profiles, ensure_ascii=False, indent=2), encoding="utf-8")


def summarize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "total_events": int(profile.get("total_events", 0) or 0),
        "top_intents": _top_items(profile.get("intent_counts", {})),
        "top_tools": _top_items(profile.get("tool_counts", {})),
        "top_targets": _top_items(profile.get("target_prefix_counts", {})),
        "external_send_rate": float(profile.get("external_send_rate", 0) or 0),
        "avg_batch_size": float(profile.get("avg_batch_size", 1) or 1),
        "avg_risk_score": float(profile.get("avg_risk_score", 0) or 0),
    }


def profile_confidence(total_events: int) -> float:
    if total_events <= 0:
        return 0.0
    return round(min(1.0, total_events / 30), 2)


def extract_target_prefix(event: ToolEvent | None) -> str:
    if event is None:
        return ""
    target = str(
        event.params.get("path")
        or event.params.get("target")
        or event.params.get("file")
        or event.params.get("destination")
        or ""
    ).replace("\\", "/")
    parts = [part for part in target.split("/") if part]
    return f"{parts[0]}/" if parts else ""


def estimate_batch_size(event: ToolEvent | None) -> int:
    if event is None:
        return 1
    params_text = json.dumps(event.params, ensure_ascii=False)
    lowered = params_text.lower()
    emails = params_text.count("@")
    separators = max(params_text.count(","), params_text.count(";"), params_text.count("\n"))
    if emails:
        return max(1, emails)
    if any(marker in lowered for marker in ["batch", "mass", "bulk", "all", "\u6279\u91cf", "\u7fa4\u53d1", "\u5168\u4f53", "\u5168\u90e8"]):
        return max(5, separators + 1)
    return 1


def is_external_action(event: ToolEvent | None) -> bool:
    if event is None:
        return False
    text = f"{event.name} {event.params}".lower()
    if has_negative_external_context(text) and not any(
        marker in text
        for marker in ["@", "http://", "https://", "ftp://", "sftp://", "s3://", "send_to_external", "external-demo"]
    ):
        return False
    if event.name not in {"send_email", "upload_file"} and not any(
        marker in text
        for marker in ["@", "http://", "https://", "external", "partner@", "\u5916\u90e8"]
    ):
        return False
    external_markers = ["send_email", "upload_file", "external", "upload", "http://", "https://", "\u90ae\u4ef6", "\u5916\u53d1"]
    return any(marker in text for marker in external_markers)


def has_negative_external_context(text: str) -> bool:
    return any(
        marker in text
        for marker in [
            "\u4e0d\u5916\u53d1",
            "\u672a\u5916\u53d1",
            "\u65e0\u5916\u53d1",
            "\u4e0d\u53d1\u9001",
            "\u672a\u53d1\u9001",
            "\u4e0d\u4e0a\u4f20",
            "\u672a\u4e0a\u4f20",
            "do not send",
            "not sent",
            "do not email",
            "no email",
            "no external",
            "do not upload",
            "not uploaded",
            "no upload",
            "local only",
        ]
    )


def _empty_profile() -> dict[str, Any]:
    return {
        "total_events": 0,
        "intent_counts": {},
        "tool_counts": {},
        "target_prefix_counts": {},
        "external_send_count": 0,
        "external_send_rate": 0.0,
        "avg_batch_size": 1.0,
        "avg_risk_score": 0.0,
    }


def _inc(profile: dict[str, Any], key: str, value: str) -> None:
    bucket = dict(profile.get(key, {}) or {})
    bucket[value] = int(bucket.get(value, 0) or 0) + 1
    profile[key] = bucket


def _update_average(profile: dict[str, Any], key: str, value: float) -> None:
    total = max(1, int(profile.get("total_events", 1) or 1))
    old = float(profile.get(key, 0) or 0)
    profile[key] = round(old + ((float(value) - old) / total), 4)


def _rare(profile: dict[str, Any], key: str, value: str) -> bool:
    counts = dict(profile.get(key, {}) or {})
    total = sum(int(item or 0) for item in counts.values())
    if total <= 0:
        return False
    return (int(counts.get(value, 0) or 0) / total) < 0.08


def _top_items(value: Any, limit: int = 5) -> list[tuple[str, int]]:
    if not isinstance(value, dict):
        return []
    counter = Counter({str(key): int(count or 0) for key, count in value.items()})
    return counter.most_common(limit)
