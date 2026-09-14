from __future__ import annotations

import json
import gzip
import hmac
import hashlib
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from threading import Lock
from functools import lru_cache
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from agentmeter_gov.audit import build_audit_report, save_report
from agentmeter_gov import __version__
from agentmeter_gov.case_loader import case_to_dict, load_case_files
from agentmeter_gov.config import load_settings
from agentmeter_gov.boot_session import monitoring_boot_started_at
from agentmeter_gov.event_protocol import validate_event_structure
from agentmeter_gov.evaluation import build_metrics
from agentmeter_gov.event_store import EventStore
from agentmeter_gov.review_state import reconcile_reviews, task_status
from agentmeter_gov.gate import evaluate_tool_gate
from agentmeter_gov.risk_engine import ACTION_THRESHOLDS, SCORING_RULES, SECURITY_POLICY, WEIGHTS, RiskEngine
from agentmeter_gov.schema import ToolEvent
from agentmeter_gov.semantic_risk import semantic_backend
from agentmeter_gov.supply_chain import scan_component, scan_to_task_case


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "data" / "demo_cases.json"
IMPORTED_FILE = ROOT / "data" / "openclaw_imported_cases.json"
FRONTEND = ROOT / "frontend"
REPORT_DIR = ROOT / "audit_reports"
FULL_45_RESULT = ROOT / "data" / "group1_full_openclaw_live_results_latest.json"
BENIGN_RESULT = ROOT / "data" / "group1_full_openclaw_live_results_subset_ben-01_ben-02_ben-03_ben-04_ben-05_ben-06_20260810.json"
SECURITY_DEFENSE_RESULT = ROOT / "data" / "security_defense_test_results.json"
REDTEAM_RESULT = ROOT / "data" / "redteam_attack_suite_results.json"
APPROVAL_FILE = ROOT / "data" / "openclaw_guard_approvals.json"
SUPPLY_CHAIN_CLEAN_RESULT = ROOT / "data" / "supply_chain_skill_clean_result.json"
SUPPLY_CHAIN_DRIFT_RESULT = ROOT / "data" / "supply_chain_skill_drift_result.json"
DESKTOP_PET_EVENTS = {
    "show": r"Local\AgentMeterGovDesktopPetShow",
    "hide": r"Local\AgentMeterGovDesktopPetHide",
}


def _signal_desktop_pet(event_name: str) -> bool:
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    event_modify_state = 0x0002
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenEventW.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.OpenEventW.restype = wintypes.HANDLE
    kernel32.SetEvent.argtypes = (wintypes.HANDLE,)
    kernel32.SetEvent.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenEventW(event_modify_state, False, event_name)
    if not handle:
        return False
    try:
        return bool(kernel32.SetEvent(handle))
    finally:
        kernel32.CloseHandle(handle)


def _desktop_pet_launcher() -> Path | None:
    candidates = (
        Path(sys.executable).resolve().parent.parent / "desktop" / "launch_desktop_pet.vbs",
        ROOT.parent / "scripts" / "launch_desktop_pet.vbs",
        ROOT.parent.parent / "desktop" / "launch_desktop_pet.vbs",
    )
    return next((path for path in candidates if path.is_file()), None)


def control_desktop_pet(action: str) -> dict:
    if action not in DESKTOP_PET_EVENTS:
        raise ValueError("action must be show or hide")
    if os.name != "nt":
        raise OSError("desktop pet control is only available on Windows")

    if _signal_desktop_pet(DESKTOP_PET_EVENTS[action]):
        return {
            "accepted": True,
            "action": action,
            "state": "visible" if action == "show" else "hidden",
            "message": "桌宠已显示" if action == "show" else "桌宠已隐藏到屏幕边缘",
        }

    if action == "hide":
        return {
            "accepted": True,
            "action": action,
            "state": "hidden",
            "message": "桌宠当前未运行",
        }

    launcher = _desktop_pet_launcher()
    if launcher is None:
        raise FileNotFoundError("desktop pet launcher not found")
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen(
        ["wscript.exe", str(launcher)],
        cwd=str(launcher.parent),
        close_fds=True,
        creationflags=creation_flags,
    )
    return {
        "accepted": True,
        "action": action,
        "state": "starting",
        "message": "桌宠正在启动",
    }


SETTINGS = load_settings()
FLOW_LOGS = SETTINGS.flow_log_paths
EVENT_STORE = EventStore(SETTINGS.database_url, SETTINGS.audit_signing_key)
SERVER_STARTED_AT = datetime.now(timezone.utc)

PHONE_RE = re.compile(r"\b1[3-9]\d{9}\b")
CHINA_ID_RE = re.compile(r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9xX]\b")
EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)


LIVE_EVENT_TYPES = {
    "input_event",
    "risk_decision_event",
    "pending_review_event",
    "approval_event",
    "guard_switch_event",
    "tool_event",
    "result_event",
    "supply_chain_scan_event",
    "output_guard_event",
    "output_postflight_event",
    "memory_governance_event",
    "subagent_event",
    "audit_integrity_event",
}
DECISION_ACTIONS = {
    "allow",
    "human_review",
    "human_review_approved",
    "block",
}
_LIVE_EVENT_CACHE = {"expires_at": 0.0, "key": "", "events": [], "ignored_record_count": 0}
_LIVE_EVENT_CACHE_LOCK = Lock()
_LIVE_EVENT_CACHE_TTL = 5.0
_LIVE_EVENT_WINDOWS: dict[tuple, tuple[list[dict], int]] = {}
_FLOW_EVENT_SNAPSHOTS: dict[tuple, tuple[dict, int]] = {}
_TASK_RESPONSE_CACHE: dict[tuple, dict] = {}
_TASK_RESPONSE_LOCK = Lock()


def _read_flow_snapshot(path: Path, index: int, since: str) -> tuple[dict, int]:
    """A database append must not force reparsing every unchanged rotated log."""
    try:
        info = path.stat()
    except FileNotFoundError:
        return {}, 0
    key = (str(path), index, since, info.st_mtime_ns, info.st_size)
    if key in _FLOW_EVENT_SNAPSHOTS:
        return _FLOW_EVENT_SNAPSHOTS[key]
    events, ignored = {}, 0
    since_at = _parse_iso(since) if since else None
    # File iteration splits actual JSONL newlines, not Unicode separators in strings.
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line_index, line in enumerate(stream):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                validate_event_structure(item)
                if since_at:
                    at = _parse_iso(str(item.get("timestamp", "")))
                    if at is None or at < since_at:
                        continue
                if item.get("event_type") in LIVE_EVENT_TYPES:
                    event_key = str(item.get("event_id") or f"jsonl:{index}:{line_index}:{item.get('timestamp', '')}")
                    events[event_key] = redact_for_dashboard(slim_event(item, validated=True))
            except (json.JSONDecodeError, TypeError, ValueError, AttributeError, RecursionError, OverflowError):
                ignored += 1
    for old_key in list(_FLOW_EVENT_SNAPSHOTS):
        if old_key[:3] == key[:3]:
            del _FLOW_EVENT_SNAPSHOTS[old_key]
    if len(_FLOW_EVENT_SNAPSHOTS) >= 16:
        del _FLOW_EVENT_SNAPSHOTS[next(iter(_FLOW_EVENT_SNAPSHOTS))]
    _FLOW_EVENT_SNAPSHOTS[key] = (events, ignored)
    return events, ignored


def _monitoring_source_revision() -> tuple:
    """Invalidate read caches when the underlying evidence changes, not on a timer."""
    paths = list(FLOW_LOGS)
    if SETTINGS.database_url.startswith("sqlite:///"):
        database = Path(EVENT_STORE.database_url.removeprefix("sqlite:///"))
        paths.extend((database, Path(str(database) + "-wal"), Path(str(database) + "-journal")))
    fingerprints = []
    for path in paths:
        try:
            stat = path.stat()
            fingerprints.append((str(path), stat.st_mtime_ns, stat.st_size))
        except FileNotFoundError:
            fingerprints.append((str(path), None, None))
    head = EVENT_STORE.chain_head() if not EVENT_STORE.database_url.startswith("sqlite:///") else {}
    return (EVENT_STORE.database_url, tuple(fingerprints), head.get("latest_sequence"), head.get("head_signature"))


def load_live_events(since: str = "") -> list[dict]:
    now = time.monotonic()
    with _LIVE_EVENT_CACHE_LOCK:
        revision = _monitoring_source_revision()
        if _LIVE_EVENT_CACHE["expires_at"] == 0:
            _LIVE_EVENT_WINDOWS.clear()
        cache_key = (since, revision)
        cached = _LIVE_EVENT_WINDOWS.get(cache_key)
        if cached is not None:
            _LIVE_EVENT_CACHE.update(key=since, events=cached[0], ignored_record_count=cached[1], expires_at=now + _LIVE_EVENT_CACHE_TTL)
            return cached[0]
        # Only retain windows from the current source revision. Switching between
        # current boot and history must not trigger a second full-history parse.
        for key in list(_LIVE_EVENT_WINDOWS):
            if key[1] != revision:
                del _LIVE_EVENT_WINDOWS[key]
        # Keep one cold load in flight. The monitoring page requests tasks and
        # health concurrently; allowing both threads to parse the full audit
        # history doubles CPU and made mature installations time out.
        events_by_id: dict[str, dict] = {}
        ignored_record_count = 0
        for log_index, flow_log in enumerate(FLOW_LOGS):
            snapshot, ignored = _read_flow_snapshot(flow_log, log_index, since)
            events_by_id.update(snapshot)
            ignored_record_count += ignored
        store_diagnostics: dict[str, int] = {}
        for item in EVENT_STORE.list_events(
            limit=None,
            ascending=True,
            since=since,
            diagnostics=store_diagnostics,
        ):
            try:
                validate_event_structure(item)
                if item.get("event_type") in LIVE_EVENT_TYPES:
                    key = str(item.get("event_id") or f"db:{len(events_by_id)}:{item.get('timestamp', '')}")
                    events_by_id[key] = redact_for_dashboard(slim_event(item, validated=True))
            except (TypeError, ValueError, AttributeError, RecursionError, OverflowError):
                ignored_record_count += 1
                continue
        ignored_record_count += store_diagnostics.get("invalid_records", 0)
        events = list(events_by_id.values())
        events.sort(key=lambda item: (_parse_iso(str(item.get("timestamp", ""))) or datetime.min.replace(tzinfo=timezone.utc), str(item.get("event_id", ""))))

        _LIVE_EVENT_CACHE["key"] = since
        _LIVE_EVENT_CACHE["events"] = events
        _LIVE_EVENT_CACHE["ignored_record_count"] = ignored_record_count
        _LIVE_EVENT_CACHE["expires_at"] = time.monotonic() + _LIVE_EVENT_CACHE_TTL
        if len(_LIVE_EVENT_WINDOWS) >= 4:
            del _LIVE_EVENT_WINDOWS[next(iter(_LIVE_EVENT_WINDOWS))]
        _LIVE_EVENT_WINDOWS[cache_key] = (events, ignored_record_count)
        return events


def monitoring_data_quality() -> dict:
    with _LIVE_EVENT_CACHE_LOCK:
        ignored = _LIVE_EVENT_CACHE.get("ignored_record_count", 0)
    return {
        "status": "partial" if ignored else "complete",
        "ignored_record_count": ignored,
        "scope": "loaded_audit_sources",
        "note": "已忽略格式异常记录；原始审计数据保留，计数覆盖已加载来源，非本次开机事件数。" if ignored else "",
    }


def read_live_events(
    limit: int | None = 80,
    since: str = "",
    until: str = "",
    offset: int = 0,
    action: str = "",
) -> list[dict]:
    if limit is not None:
        limit = max(1, min(limit, 500))
    offset = max(0, offset)
    events: list[dict] = []
    since_at = _parse_iso(since) if since else None
    until_at = _parse_iso(until) if until else None
    for event in reversed(load_live_events(since=since)):
        timestamp = str(event.get("timestamp", ""))
        event_at = _parse_iso(timestamp)
        if since_at and (event_at is None or event_at < since_at):
            continue
        if until_at and (event_at is None or event_at >= until_at):
            continue
        if action and not _matches_action(event, action):
            continue
        events.append(event)
        if limit is not None and len(events) >= offset + limit:
            break
    page = events[offset:] if limit is None else events[offset : offset + limit]
    return list(reversed(page))


def live_event_count(since: str = "", until: str = "", action: str = "") -> int:
    return len(read_live_events(limit=None, since=since, until=until, action=action))


def _matches_action(event: dict, action: str) -> bool:
    gate_action = str(event.get("gate_action") or "")
    return gate_action == action or gate_action.startswith(f"{action}_")


_FACTOR_KEEP_FIELDS = ("code", "name", "zh_name", "score", "weight", "contribution", "evidence")


def _slim_factor_contributions(contributions) -> dict:
    if not isinstance(contributions, dict):
        return {}
    slim: dict[str, dict] = {}
    for code, factor in contributions.items():
        if not isinstance(factor, dict):
            continue
        slim[str(code)] = {
            key: factor.get(key)
            for key in _FACTOR_KEEP_FIELDS
            if factor.get(key) is not None
        }
    return slim


def _slim_threshold(threshold) -> dict:
    if not isinstance(threshold, dict):
        return {}
    return {
        key: threshold.get(key)
        for key in ("score", "band", "level", "zh_level", "action", "model_action", "explanation")
        if threshold.get(key) is not None
    }


def slim_event(item: dict, *, validated: bool = False) -> dict:
    if not validated:
        validate_event_structure(item)
    proposed = item.get("proposed_tool_call") or {}
    security_control = item.get("security_control") or {}
    scoring_details = item.get("scoring_details") or {}
    return {
        "schema_version": item.get("schema_version", ""),
        "adapter": item.get("adapter", ""),
        "protocol_stage": item.get("protocol_stage", ""),
        "timestamp": item.get("timestamp", ""),
        "event_id": item.get("event_id", ""),
        "event_type": item.get("event_type", ""),
        "session_key": item.get("session_key", ""),
        "run_id": item.get("run_id", ""),
        "task_id": item.get("task_id", ""),
        "audit_id": item.get("audit_id", ""),
        "parent_audit_id": item.get("parent_audit_id", ""),
        "user_goal": item.get("user_goal", ""),
        "tool_name": item.get("tool_name") or proposed.get("name") or item.get("action") or "",
        "gate_action": item.get("gate_action") or item.get("decision") or item.get("action") or "",
        "status": item.get("status", ""),
        "execution_result": item.get("execution_result", ""),
        "allowed": item.get("allowed"),
        "risk_score": item.get("risk_score"),
        "triggered_rules": [
            str(rule.get("rule_id") or rule.get("code") or rule.get("name") or json.dumps(rule, ensure_ascii=False))
            if isinstance(rule, dict) else str(rule)
            for rule in (item.get("triggered_rules") or [])
        ],
        "evidence": item.get("evidence", ""),
        "proposed_tool_call": proposed,
        "parameters": item.get("parameters") or proposed.get("params") or {},
        "target": item.get("target") or _event_target(item, proposed),
        "sensitivity": item.get("sensitivity") or proposed.get("data_level") or "",
        "recipients": _event_recipients(item, proposed),
        "factor_contributions": _slim_factor_contributions(
            item.get("factor_contributions")
            or scoring_details.get("factor_contributions")
            or {}
        ),
        "threshold_explanation": _slim_threshold(
            item.get("threshold_explanation")
            or scoring_details.get("threshold_explanation")
            or _threshold_from_score(item.get("risk_score"), item.get("gate_action") or item.get("decision") or item.get("action"))
        ),
        "recovery_plan": item.get("recovery_plan")
        or security_control.get("recovery_plan")
        or scoring_details.get("recovery_plan")
        or {},
        "recovery_execution": item.get("recovery_execution")
        or security_control.get("recovery_execution")
        or scoring_details.get("recovery_execution")
        or {},
        "taint_summary": security_control.get("taint_summary") or scoring_details.get("taint_summary") or {},
        "batch_analysis": security_control.get("batch_analysis") or scoring_details.get("batch_analysis") or {},
        "control_ids": [
            item.get("control_id")
            for item in (security_control.get("controls") or [])
            if isinstance(item, dict) and item.get("control_id")
        ],
        "guard_enabled": item.get("guard_enabled"),
        "mode": item.get("mode"),
        "approval_id": item.get("approval_id") or "",
        "review_id": item.get("review_id") or "",
        "review_decision": item.get("review_decision") or "",
        "approval_scope": item.get("approval_scope") or "",
        "call_id": item.get("call_id") or "",
        "tool_call_id": item.get("tool_call_id") or "",
        "operation_id": item.get("operation_id") or "",
        "surface": item.get("surface", ""),
        "findings": item.get("findings") or [],
        "memory_path": item.get("memory_path", ""),
        "memory_operation": item.get("memory_operation", ""),
        "memory_classification": item.get("memory_classification", ""),
        "lineage_id": item.get("lineage_id", ""),
        "tainted": item.get("tainted"),
        "child_session_key": item.get("child_session_key", ""),
        "inherited_authorization": item.get("inherited_authorization") or [],
        "inherited_data_level": item.get("inherited_data_level", ""),
        "audit_signature": item.get("audit_signature", ""),
        "previous_signature": item.get("previous_signature", ""),
        "gate_latency_ms": item.get("gate_latency_ms"),
        "gate_transport": item.get("gate_transport") or {},
        "gate_timings_ms": item.get("gate_timings_ms") or {},
    }


def _event_recipients(item: dict, proposed: dict) -> list[str]:
    name = item.get("tool_name") or proposed.get("name") or ""
    if name not in {"send_email", "upload_file"}:
        return []
    params = item.get("parameters") or proposed.get("params") or {}
    # Parse before redaction using the gate's draft/structured-field precedence.
    # Mask here as well so new recipients cannot bypass dashboard redaction.
    event = ToolEvent(name=name, params=params, source="dashboard")
    return [_mask_email(address) for address in RiskEngine()._recipient_addresses(event)]


def _event_target(item: dict, proposed: dict) -> str:
    params = item.get("parameters") or proposed.get("params") or {}
    if not isinstance(params, dict):
        return ""
    for key in ("path", "file", "target", "to", "url", "destination", "attachment"):
        value = params.get(key)
        if value:
            return str(value).replace("\\", "/")
    return ""


def _threshold_from_score(score, action: str | None) -> dict:
    if not isinstance(score, int):
        return {}
    if score < 40:
        band = "0-39"
        model_action = "allow"
        level = "low"
        explanation = "低风险区间：允许执行并保留基础审计。"
    elif score < 75:
        band = "40-74"
        model_action = "human_review"
        level = "review"
        explanation = "复核区间：存在关键风险因子，需要人工确认后执行。"
    else:
        band = "75-100"
        model_action = "block"
        level = "block"
        explanation = "阻断区间：命中高风险链路，应在工具执行前拦截。"
    return {
        "score": score,
        "band": band,
        "level": level,
        "action": action or model_action,
        "model_action": model_action,
        "explanation": explanation,
    }


def safe_read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    visible = local[:2] if len(local) >= 2 else local[:1]
    return f"{visible}***@{domain}" if domain else "[EMAIL_REDACTED]"


_SECRET_FIELD_RE = re.compile(r"token|api_key|apikey|password|secret|credential", re.IGNORECASE)
_INLINE_SECRET_RE = re.compile(r"(token|api[_-]?key|password|secret|credential)\s*[:=]\s*\S+", re.IGNORECASE)


def _redact_text(value: str) -> str:
    text = CHINA_ID_RE.sub("[CHINA_ID_REDACTED]", value)
    text = PHONE_RE.sub("[PHONE_REDACTED]", text)
    text = EMAIL_RE.sub(lambda match: _mask_email(match.group(0)), text)
    return _INLINE_SECRET_RE.sub(r"\1=[SECRET_REDACTED]", text)


_redact_short_text = lru_cache(maxsize=8192)(_redact_text)


def redact_for_dashboard(value, key: str = ""):
    # Tool parameters also occur inside proposed_tool_call. Process shared
    # containers once, without removing fields or touching signed source data.
    containers: dict[int, object] = {}
    strings: dict[str, str] = {}

    def visit(item, field=""):
        if isinstance(item, (dict, list)):
            identity = id(item)
            if identity in containers:
                return containers[identity]
            result = {str(k): visit(v, str(k)) for k, v in item.items()} if isinstance(item, dict) else [visit(child) for child in item]
            containers[identity] = result
            return result
        if not isinstance(item, str):
            return item
        if _SECRET_FIELD_RE.search(field):
            return "[SECRET_REDACTED]"
        if item not in strings:
            strings[item] = _redact_short_text(item) if len(item) <= 1024 else _redact_text(item)
        return strings[item]

    return visit(value, key)


def _parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
        return parsed.replace(tzinfo=timezone.utc) if parsed and parsed.tzinfo is None else parsed
    except (TypeError, ValueError):
        return None


def _task_key(event: dict) -> str:
    return str(event.get("task_id") or event.get("run_id") or event.get("session_key") or event.get("event_id") or "unknown-task")


def _task_status(events: list[dict]) -> str:
    return task_status(events, reconcile_reviews({"task": events})["task"])


def _build_task_item(key: str, events: list[dict], reviews: list[dict] | None = None) -> dict:
    if reviews is None:
        reviews = reconcile_reviews({key: events})[key]
    decisions = [event for event in events if event.get("event_type") == "risk_decision_event"]
    inputs = [event for event in events if event.get("event_type") == "input_event" and event.get("user_goal")]
    scores = [event.get("risk_score") for event in decisions if isinstance(event.get("risk_score"), int)]
    tools = list(dict.fromkeys(str(event.get("tool_name") or "") for event in events if event.get("tool_name")))
    targets = list(dict.fromkeys(str(event.get("target") or "") for event in events if event.get("target")))
    status = task_status(events, reviews)
    latest = events[-1] if events else {}
    latest_decision = decisions[-1] if decisions else None
    peak_decision = max(
        decisions,
        key=lambda event: event.get("risk_score") if isinstance(event.get("risk_score"), int) else -1,
        default=None,
    )
    return {
        "task_key": key,
        "task_id": str(latest.get("task_id") or key),
        # This payload is assembled from the runtime audit stream exposed by
        # /api/live/tasks. Mark the task wrapper explicitly so the monitor does
        # not mislabel a real runtime record as an unknown source.
        "source_kind": "live",
        "task_origin": "openclaw_user_message",
        "task_definition": "one_openclaw_user_message",
        "session_key": str(latest.get("session_key") or ""),
        "run_id": str(latest.get("run_id") or ""),
        "goal": str(inputs[-1].get("user_goal") or "") if inputs else "",
        "goal_source": "audit_input_event" if inputs else "unavailable",
        "started_at": str(events[0].get("timestamp") or "") if events else "",
        "ended_at": str(latest.get("timestamp") or ""),
        "status": status,
        "outcome_status": status,
        "protection_layer": "agentmeter_guard" if decisions else "audit_observation",
        "attribution_explanation": (
            "OpenClaw 已提出工具请求，由 AgentMeter-Gov 在工具执行前判定。"
            if decisions else "只记录到审计活动，尚未形成 AgentMeter-Gov 风险判定。"
        ),
        "assistant_summary": "",
        "event_count": len(events),
        "decision_count": len(decisions),
        "tool_event_count": sum(event.get("event_type") == "tool_event" for event in events),
        "review_count": len(reviews),
        "pending_review_count": sum(review["state"] == "pending" for review in reviews),
        "reviews": reviews,
        "max_risk_score": max(scores) if scores else None,
        "peak_risk_score": peak_decision.get("risk_score") if peak_decision else None,
        "peak_action": str(peak_decision.get("gate_action") or "") if peak_decision else "",
        "latest_action": str(latest_decision.get("gate_action") or "") if latest_decision else "",
        "latest_decision": latest_decision,
        "peak_decision": peak_decision,
        "tools": tools,
        "targets": targets,
        "events": events,
    }


def build_task_history(since: str = "", until: str = "", query_text: str = "", active_only: bool = False, task_limit: int | None = 200) -> dict:
    grouped: dict[str, list[dict]] = {}
    for event in read_live_events(limit=None, since=since, until=until):
        grouped.setdefault(_task_key(event), []).append(event)
    # Approval commands can arrive as a new user task. Join by review ID before
    # filtering or paginating tasks, while keeping each raw event in its own task.
    reviews = reconcile_reviews(grouped)
    tasks = [_build_task_item(key, events, reviews[key]) for key, events in grouped.items()]
    tasks = [task for task in tasks if task.get("goal")]
    now = datetime.now(timezone.utc)
    active_window_seconds = 180
    for task in tasks:
        latest_at = _parse_iso(str(task.get("ended_at") or ""))
        if task.get("status") == "running" and (
            latest_at is None or (now - latest_at).total_seconds() > active_window_seconds
        ):
            task["status"] = "incomplete"
            task["outcome_status"] = "incomplete"
    if active_only:
        tasks = [
            task for task in tasks
            if (
                task.get("status") == "running"
                and (latest_at := _parse_iso(str(task.get("ended_at") or ""))) is not None
                and 0 <= (now - latest_at).total_seconds() <= active_window_seconds
            )
        ]
    tasks.sort(key=lambda item: str(item.get("ended_at") or ""), reverse=True)
    if query_text:
        query = query_text.lower()
        tasks = [task for task in tasks if query in json.dumps(task, ensure_ascii=False, default=str).lower()]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task_definition": "每条任务对应一次用户发送给 OpenClaw 的文字消息，相关工具调用和安全处置归入同一条记录。",
        "task_count": len(tasks),
        "returned_task_count": len(tasks if task_limit is None else tasks[:task_limit]),
        "event_count": sum(int(task.get("event_count") or 0) for task in tasks),
        "active_only": active_only,
        "active_window_seconds": active_window_seconds if active_only else None,
        "tasks": tasks if task_limit is None else tasks[:task_limit],
    }


def load_review_center() -> dict:
    store = safe_read_json(APPROVAL_FILE, {"pending": [], "approvals": [], "rejections": []})
    if not isinstance(store, dict):
        store = {"pending": [], "approvals": [], "rejections": []}
    approvals = {str(item.get("reviewId", "")): item for item in store.get("approvals", []) if isinstance(item, dict)}
    rejections = {str(item.get("reviewId", "")): item for item in store.get("rejections", []) if isinstance(item, dict)}
    now = datetime.now(timezone.utc)
    items = []
    for item in store.get("pending", []):
        if not isinstance(item, dict):
            continue
        review_id = str(item.get("reviewId", ""))
        approval = approvals.get(review_id)
        rejection = rejections.get(review_id)
        expires_at = str((approval or {}).get("expiresAt", ""))
        expires = _parse_iso(expires_at)
        if item.get("rejected") or rejection:
            status = "rejected"
        elif approval and approval.get("consumed"):
            status = "released_once"
        elif approval and expires and expires < now:
            status = "approval_expired"
        elif approval:
            status = "approved_waiting_retry"
        elif item.get("consumed"):
            status = "closed"
        else:
            status = "pending"
        proposed = item.get("proposedToolCall", {}) if isinstance(item.get("proposedToolCall"), dict) else {}
        params = proposed.get("params", {}) if isinstance(proposed.get("params"), dict) else {}
        target = next((str(params[key]) for key in ("path", "file", "target", "to", "url", "destination", "attachment") if params.get(key)), "")
        items.append({
            "review_id": review_id,
            "status": status,
            "created_at": item.get("createdAt", ""),
            "expires_at": expires_at,
            "task_id": item.get("taskId", ""),
            "session_key": item.get("sessionKey", ""),
            "risk_score": item.get("riskScore", 0),
            "tool_name": proposed.get("name", ""),
            "target": redact_for_dashboard(target),
            "redacted_params": redact_for_dashboard(params),
            "matched_rules": item.get("matchedRules", []),
            "approve_command": f"审批通过 {review_id}" if review_id else "",
            "reject_command": f"审批拒绝 {review_id}" if review_id else "",
        })
    items.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return {
        "generated_at": now.isoformat(),
        "store_exists": APPROVAL_FILE.exists(),
        "items": items[:100],
        "note": "网页只展示脱敏后的复核状态；批准或拒绝仍通过 OpenClaw 会话命令完成。",
    }


def build_runtime_health(since: str = "") -> dict:
    now = datetime.now(timezone.utc)
    events = read_live_events(limit=None, since=since) if since else load_live_events()
    latest = events[-1] if events else {}
    latest_at = _parse_iso(str(latest.get("timestamp") or ""))
    age_seconds = max(0, int((now - latest_at).total_seconds())) if latest_at else None
    activity_state = "never_seen" if age_seconds is None else "recent" if age_seconds <= 120 else "idle" if age_seconds <= 3600 else "stale"
    effective_state = "active" if activity_state == "recent" else "awaiting_plugin_activity"
    audit_paths = [str(path) for path in FLOW_LOGS]
    return {
        "generated_at": now.isoformat(),
        "server": {"status": "healthy", "bind": f"{SETTINGS.host}:{SETTINGS.port}", "started_at": SERVER_STARTED_AT.isoformat(), "uptime_seconds": int((now - SERVER_STARTED_AT).total_seconds()), "python": sys.version.split()[0]},
        "plugin": {"activity_state": activity_state, "last_seen": latest.get("timestamp", ""), "last_event_type": latest.get("event_type", ""), "last_session": latest.get("session_key", ""), "age_seconds": age_seconds, "note": "插件状态依据最近一条真实事件判断。"},
        "guard": {"configured_mode": "mandatory_enforce", "effective_state": effective_state, "fail_closed_default": True, "evidence": "风险服务正常；插件在线性依据最近真实事件单独判断。"},
        "rules": {"rules_version": SCORING_RULES.get("version", "unknown"), "policy_version": SECURITY_POLICY.get("version", "unknown"), "semantic_backend": semantic_backend(), "weights": WEIGHTS, "thresholds": ACTION_THRESHOLDS},
        "audit": {"paths": audit_paths, "event_count": len(events), "database": SETTINGS.database_url.split(":", 1)[0]},
    }


def _percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 1) if denominator else 0.0


def build_evaluation_summary() -> dict:
    full = safe_read_json(FULL_45_RESULT, {})
    benign = safe_read_json(BENIGN_RESULT, {})
    defense = safe_read_json(SECURITY_DEFENSE_RESULT, {})
    redteam = safe_read_json(REDTEAM_RESULT, {})
    metrics = full.get("metrics", {}) if isinstance(full, dict) else {}
    benign_metrics = benign.get("metrics", {}) if isinstance(benign, dict) else {}
    malicious_total = int(metrics.get("malicious_valid_cases", 0) or 0)
    contained = int(metrics.get("comprehensive_defense_success", 0) or 0)
    direct = int(metrics.get("agentmeter_direct_intervention_success", 0) or 0)
    benign_total = int(benign_metrics.get("benign_valid_cases", metrics.get("benign_valid_cases", 0)) or 0)
    false_positive = int(benign_metrics.get("benign_false_positive", metrics.get("benign_false_positive", 0)) or 0)
    verdicts = redteam.get("verdicts", {}) if isinstance(redteam, dict) else {}
    redteam_total = int(redteam.get("total", 0) or 0) if isinstance(redteam, dict) else 0
    comparisons = []
    for item in full.get("results", []) if isinstance(full, dict) else []:
        if isinstance(item, dict) and str(item.get("label", "")) in {"恶意", "malicious"}:
            comparisons.append({"case_id": item.get("case_id", ""), "risk_type": item.get("risk_type", ""), "method": item.get("method", ""), "baseline_actual": item.get("baseline_actual", ""), "protected_actions": item.get("observed_actions", []), "max_score": item.get("max_score"), "verdict": item.get("verdict", "")})
        if len(comparisons) >= 12:
            break
    sources = []
    for path in (FULL_45_RESULT, BENIGN_RESULT, SECURITY_DEFENSE_RESULT, REDTEAM_RESULT):
        sources.append({"file": path.name, "exists": path.exists(), "updated_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat() if path.exists() else ""})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rules_version": SCORING_RULES.get("version", "unknown"),
        "policy_version": SECURITY_POLICY.get("version", "unknown"),
        "headline": {"malicious_total": malicious_total, "malicious_contained": contained, "malicious_containment_rate": _percent(contained, malicious_total), "agentmeter_direct": direct, "agentmeter_direct_rate": _percent(direct, malicious_total), "model_safe_before_tool": max(0, contained - direct), "benign_total": benign_total, "benign_pass": max(0, benign_total - false_positive), "benign_pass_rate": _percent(max(0, benign_total - false_positive), benign_total), "false_positive": false_positive, "false_positive_rate": _percent(false_positive, benign_total), "redteam_total": redteam_total, "redteam_pass": int(verdicts.get("PASS", 0) or 0), "redteam_exact_rate": _percent(int(verdicts.get("PASS", 0) or 0), redteam_total), "redteam_overblock": sum(int(value or 0) for key, value in verdicts.items() if "OVER" in str(key).upper())},
        "security_defense": {"total": defense.get("total", 0) if isinstance(defense, dict) else 0, "passed": defense.get("passed", 0) if isinstance(defense, dict) else 0},
        "redteam_by_category": redteam.get("by_category", {}) if isinstance(redteam, dict) else {},
        "comparisons": comparisons,
        "sources": sources,
        "note": "模型先行拒绝与 AgentMeter-Gov 工具门禁介入分开统计。",
    }


def supply_chain_sample_summaries() -> list[dict]:
    summaries = []
    for label, path in (("可信基线样例", SUPPLY_CHAIN_CLEAN_RESULT), ("漂移风险样例", SUPPLY_CHAIN_DRIFT_RESULT)):
        data = safe_read_json(path, {})
        scan = data.get("scan", data) if isinstance(data, dict) else {}
        decision = data.get("risk_measurement", {}) if isinstance(data, dict) else {}
        summaries.append({"label": label, "source": path.name, "component": scan.get("component", {}), "baseline_component": scan.get("baseline_component", {}), "risk_score": decision.get("total_score", scan.get("risk_score", 0)), "recommendation": decision.get("action", scan.get("recommendation", "unknown")), "drift_flags": scan.get("drift_flags", []), "added_high_risk": scan.get("high_risk_added_capabilities", []), "undeclared_high_risk": scan.get("high_risk_undeclared_capabilities", []), "file_diff": scan.get("file_diff", {}), "evidence": scan.get("evidence", [])[:8]})
    return summaries


def build_metric_drilldown(metric: str, since: str = "", until: str = "", task: str = "") -> dict:
    events = read_live_events(limit=None, since=since, until=until)
    if task:
        events = [event for event in events if str(event.get("task_id") or "") == task]
    decisions = [event for event in events if event.get("event_type") == "risk_decision_event"]
    titles = {"events": ("全部事件", "所选任务的完整审计记录。"), "interventions": ("安全介入", "人工复核或直接阻断记录。"), "high_risk": ("较高风险事件", "风险分达到 40 分及以上的判定。"), "allowed": ("已放行动作", "风险较低并允许继续的操作。"), "pending_reviews": ("待人工复核", "需要负责人确认的一次性操作。"), "plugin_activity": ("插件最近活动", "所选任务的插件事件。")}
    selected = events
    items = []
    if metric == "interventions":
        selected = [event for event in decisions if event.get("gate_action") in {"human_review", "block"}]
    elif metric == "high_risk":
        selected = [event for event in decisions if isinstance(event.get("risk_score"), int) and event["risk_score"] >= 40]
    elif metric == "allowed":
        selected = [event for event in decisions if event.get("gate_action") in {"allow", "human_review_approved"}]
    elif metric == "pending_reviews":
        selected = []
        items = [item for item in load_review_center().get("items", []) if item.get("status") == "pending" and (not task or str(item.get("task_id") or "") == task)]
    elif metric == "plugin_activity":
        selected = events[-20:]
    title, description = titles.get(metric, titles["events"])
    return {"metric": metric, "title": title, "description": description, "count": len(items) if metric == "pending_reviews" else len(selected), "events": selected[-500:], "items": items}


def build_live_summary(since: str = "", until: str = "") -> dict:
    events = read_live_events(limit=None, since=since, until=until)
    decisions = [event for event in events if event["event_type"] == "risk_decision_event"]
    latest_decision = decisions[-1] if decisions else None
    latest_input = next((event for event in reversed(events) if event["event_type"] == "input_event"), None)
    latest_event = events[-1] if events else None
    action_counts: dict[str, int] = {}
    high_risk: list[dict] = []
    for event in decisions:
        action = event.get("gate_action") or ""
        if action in DECISION_ACTIONS:
            action_counts[action] = action_counts.get(action, 0) + 1
        score = event.get("risk_score")
        if isinstance(score, int) and score >= 40:
            high_risk.append(event)

    full_metrics = load_metrics(FULL_45_RESULT)
    benign_metrics = load_metrics(BENIGN_RESULT)
    return {
        "generated_at": latest_timestamp(events),
        "since": since,
        "until": until,
        "guard": {
            "enabled": True,
            "mode": "mandatory_enforce",
            "evidence": "AgentMeter-Gov is always enforced by the OpenClaw plugin; natural-language on/off switch has been removed.",
        },
        "window": {
            "event_count": len(events),
            "decision_count": len(decisions),
            "action_counts": action_counts,
            "high_risk_count": len(high_risk),
            "latest_high_risk": high_risk[-6:],
            "latest_decision": latest_decision,
            "scoring_status": _scoring_status(latest_event, latest_input, latest_decision),
        },
        "evaluation": {
            "full_45_original": full_metrics,
            "benign_retest": benign_metrics,
            "adjusted": {
                "malicious_success_rate": "37/39 = 94.9%",
                "miss_rate": "2/39 = 5.1%",
                "benign_pass_rate": "6/6 = 100.0%",
                "false_positive_rate": "0/6 = 0.0%",
                "combined_effective_rate": "43/45 = 95.6%",
                "note": "恶意样本采用 2026-08-09 全量结果；良性样本采用 2026-08-10 修复后复测结果。最终答辩前需全量复跑确认。",
            },
        },
    }


def _scoring_status(latest_event: dict | None, latest_input: dict | None, latest_decision: dict | None) -> dict:
    if latest_decision is None:
        if latest_input is not None:
            return {
                "state": "not_triggered",
                "message": "当前窗口尚未触发工具调用，因此没有风险评分。",
            }
        return {"state": "empty", "message": "当前窗口暂无可评分事件。"}

    input_timestamp = str((latest_input or {}).get("timestamp") or "")
    decision_timestamp = str(latest_decision.get("timestamp") or "")
    latest_event_timestamp = str((latest_event or {}).get("timestamp") or "")
    if input_timestamp > decision_timestamp and latest_event_timestamp >= input_timestamp:
        return {
            "state": "not_triggered",
            "message": "最新输入未触发工具调用；当前展示最近一次真实工具风险评分。",
        }
    return {"state": "scored", "message": "已完成工具调用前风险评分。"}


def load_metrics(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        results = payload.get("results", [])
        if isinstance(results, list) and results:
            return build_metrics(results)
        return payload.get("metrics", {})
    except (OSError, json.JSONDecodeError):
        return {}


def latest_timestamp(events: list[dict]) -> str:
    for event in reversed(events):
        if event.get("timestamp"):
            return str(event["timestamp"])
    return ""


def parse_query_int(query: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(query.get(key, [str(default)])[0])
    except (TypeError, ValueError):
        return default


_build_live_summary_legacy = build_live_summary


def build_live_summary(since: str = "", until: str = "") -> dict:
    summary = _build_live_summary_legacy(since=since, until=until)
    metrics = load_metrics(FULL_45_RESULT)
    summary["evaluation"] = {
        "full_45_latest": metrics,
        "benign_retest": load_metrics(BENIGN_RESULT),
        "accounting_policy": {
            "agentmeter_direct_block": metrics.get("agentmeter_direct_block", 0),
            "agentmeter_human_review": metrics.get("agentmeter_human_review", 0),
            "agentmeter_output_gate": metrics.get("agentmeter_output_gate", 0),
            "model_self_refusal": metrics.get("model_self_refusal", 0),
            "model_self_refusal_manual_confirmed": metrics.get("model_self_refusal_manual_confirmed", 0),
            "manual_adjudication_required": metrics.get("manual_adjudication_required", 0),
            "note": "Pending adjudication is excluded; confirmed decisions are bound to a session and output hash.",
        },
    }
    return summary


def monitoring_window(query: dict[str, list[str]]) -> tuple[str, dict]:
    """Current monitoring is boot-scoped; explicit history spans saved audit data."""
    scope = query.get("scope", [""])[0]
    scoped = scope == "current"
    since = query.get("since", [""])[0]
    boot = None
    error = ""
    if scoped:
        try:
            boot = monitoring_boot_started_at()
            requested = _parse_iso(since)
            since = max(boot, requested or boot).isoformat()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            # Do not silently display yesterday's records if boot detection fails.
            error = "无法确认本次开机时间，请检查系统启动信息读取权限"
            since = datetime.max.replace(tzinfo=timezone.utc).isoformat()
    return since, {
        "monitoring_scope": "current" if scope == "current" else "history",
        "monitoring_window_kind": "boot" if scoped else "unbounded_audit",
        "monitoring_started_at": boot.isoformat() if boot else None,
        "monitoring_error": error,
    }


def compact_task_payload(payload: dict) -> dict:
    """Lossless wire representation; the monitor restores defaults and references."""
    defaults = {key: value for key, value in slim_event({}, validated=True).items()
                if value is None or value == "" or value == [] or value == {}}
    tasks, refs = [], []
    for task in payload["tasks"]:
        positions = {id(event): index for index, event in enumerate(task["events"])}
        refs.append([positions.get(id(task.get(field))) for field in ("latest_decision", "peak_decision")])
        tasks.append({**{key: value for key, value in task.items() if key not in {"events", "latest_decision", "peak_decision"}},
                      "events": [{key: value for key, value in event.items() if key not in defaults or value != defaults[key]}
                                 for event in task["events"]]})
    return {**payload, "tasks": tasks, "transport": "task-events-v1", "event_defaults": defaults, "decision_refs": refs}


def task_response(query: dict, since: str, window: dict, compressed: bool) -> dict:
    # Serialize a given revision once, and let conditional reads skip task
    # reconciliation entirely. This lock is never taken by evaluation or audit writes.
    with _TASK_RESPONSE_LOCK:
        revision = _monitoring_source_revision()
        key = (revision, since, repr(sorted(query.items())), repr(window), compressed)
        now = datetime.now(timezone.utc)
        cached = _TASK_RESPONSE_CACHE.get(key)
        if cached and cached["created"] <= now < cached["expires"]:
            return cached
        for old_key in list(_TASK_RESPONSE_CACHE):
            if old_key[0] != revision:
                del _TASK_RESPONSE_CACHE[old_key]
        payload = build_task_history(
            since=since, until=query.get("until", [""])[0], query_text=query.get("q", [""])[0],
            active_only=query.get("active", [""])[0].lower() in {"1", "true", "yes"},
            task_limit=None if query.get("scope", [""])[0] in {"current", "history"} else 200,
        )
        signature = (revision, sorted(query.items()), window,
                     [(task["task_key"], task["status"]) for task in payload["tasks"]])
        etag = '"' + hashlib.sha256(repr(signature).encode("utf-8")).hexdigest() + '"'
        payload.update(window, data_quality=monitoring_data_quality())
        # Include future timestamps and the existing 180-second status boundary,
        # even for tasks excluded by a search or active-only filter.
        expires = datetime.max.replace(tzinfo=timezone.utc)
        for event in load_live_events(since):
            at = _parse_iso(str(event.get("timestamp", "")))
            if at:
                if now < at < expires:
                    expires = at
                if at < datetime.max.replace(tzinfo=timezone.utc) - timedelta(seconds=181):
                    aged = at + timedelta(seconds=180, microseconds=1)
                    if now < aged < expires:
                        expires = aged
        if query.get("format", [""])[0] == "compact":
            payload = compact_task_payload(payload)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=asdict).encode("utf-8")
        compressed = compressed and len(body) >= 16384
        if compressed:
            body = gzip.compress(body, compresslevel=1, mtime=0)
        result = {"body": body, "etag": etag, "compressed": compressed, "created": now, "expires": expires}
        # Bound retained response bytes independently of the source evidence size.
        while _TASK_RESPONSE_CACHE and (len(_TASK_RESPONSE_CACHE) >= 4 or
                sum(len(item["body"]) for item in _TASK_RESPONSE_CACHE.values()) + len(body) > 32 * 1024 * 1024):
            del _TASK_RESPONSE_CACHE[next(iter(_TASK_RESPONSE_CACHE))]
        if len(body) <= 32 * 1024 * 1024:
            _TASK_RESPONSE_CACHE[key] = result
        return result


class AgentMeterHandler(BaseHTTPRequestHandler):
    server_version = f"AgentMeterGov/{__version__}"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json({
                "status": "ok",
                "version": __version__,
                "environment": SETTINGS.environment,
                "storage": SETTINGS.database_url.split(":", 1)[0],
                # Liveness must stay cheap even after years of audit events.
                # Full cryptographic verification remains available at
                # POST /api/audit/verify and is never part of a one-second
                # process-readiness probe.
                "audit_chain": EVENT_STORE.chain_head(),
            })
            return
        if parsed.path.startswith("/api/") and not self.authorized():
            self.send_json({"error": "unauthorized"}, status=401)
            return
        if parsed.path == "/api/cases":
            self.send_json([case_to_dict(case) for case in self.load_all_cases()])
            return
        if parsed.path.startswith("/api/run/"):
            task_id = parsed.path.rsplit("/", 1)[-1]
            case = self.find_case(task_id)
            if case is None:
                self.send_error(404, "case not found")
                return
            decision = RiskEngine().evaluate(case)
            report = build_audit_report(case, decision)
            save_report(report, REPORT_DIR)
            self.send_json(report)
            return
        if parsed.path.startswith("/api/report/"):
            task_id = parsed.path.rsplit("/", 1)[-1]
            report_path = REPORT_DIR / f"{task_id}_audit_report.json"
            if not report_path.exists():
                self.send_error(404, "report not found")
                return
            self.send_json(json.loads(report_path.read_text(encoding="utf-8")))
            return
        if parsed.path == "/api/live/events":
            query = parse_qs(parsed.query)
            limit = parse_query_int(query, "limit", 80)
            offset = parse_query_int(query, "offset", 0)
            since = query.get("since", [""])[0]
            until = query.get("until", [""])[0]
            action = query.get("action", [""])[0]
            events = read_live_events(limit=limit, since=since, until=until, offset=offset, action=action)
            total = live_event_count(since=since, until=until, action=action)
            self.send_json({
                "events": events,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(events) < total,
                "data_quality": monitoring_data_quality(),
            })
            return
        if parsed.path == "/api/live/tasks":
            query = parse_qs(parsed.query)
            since, window = monitoring_window(query)
            result = task_response(query, since, window, self.accepts_gzip())
            self.send_json_body(result["body"], etag=result["etag"], compressed=result["compressed"])
            return
        if parsed.path == "/api/live/drilldown":
            query = parse_qs(parsed.query)
            self.send_json(build_metric_drilldown(
                metric=query.get("metric", ["events"])[0],
                since=query.get("since", [""])[0],
                until=query.get("until", [""])[0],
                task=query.get("task", [""])[0],
            ))
            return
        if parsed.path == "/api/live/summary":
            query = parse_qs(parsed.query)
            since, window = monitoring_window(query)
            until = query.get("until", [""])[0]
            self.send_json({**build_live_summary(since=since, until=until), **window, "data_quality": monitoring_data_quality()})
            return
        if parsed.path == "/api/health":
            since, window = monitoring_window(parse_qs(parsed.query))
            self.send_json({**build_runtime_health(since=since), **window, "data_quality": monitoring_data_quality()})
            return
        if parsed.path == "/api/reviews":
            self.send_json(load_review_center())
            return
        if parsed.path == "/api/evaluation":
            self.send_json(build_evaluation_summary())
            return
        if parsed.path == "/api/supply-chain/samples":
            self.send_json({"items": supply_chain_sample_summaries()})
            return
        self.serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if not self.authorized():
            self.send_json({"error": "unauthorized"}, status=401)
            return
        if parsed.path == "/api/desktop-pet":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                self.send_json(control_desktop_pet(str(payload.get("action") or "")))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self.send_json({"error": f"bad desktop pet request: {exc}"}, status=400)
            except (OSError, subprocess.SubprocessError) as exc:
                self.send_json({"error": f"desktop pet control failed: {exc}"}, status=503)
            return
        if parsed.path == "/api/events":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                stored = EVENT_STORE.append(payload)
                # Source revision invalidates monitoring caches after this commit.
                # Never wait for a full monitoring-history read to acknowledge audit.
                self.send_json({"accepted": True, "event_id": stored["event_id"], "audit_signature": stored["audit_signature"]}, status=201)
            except (json.JSONDecodeError, TypeError, ValueError, RecursionError, OverflowError) as exc:
                self.send_json({"error": f"bad event payload: {exc}"}, status=400)
            return
        if parsed.path == "/api/audit/verify":
            result = EVENT_STORE.verify_chain()
            self.send_json(result, status=200 if result["valid"] else 409)
            return
        if parsed.path in {"/api/gate", "/api/v1/evaluate"}:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                result = evaluate_tool_gate(payload)
                save_started = time.perf_counter()
                save_report(result["audit_report"], REPORT_DIR)
                result["gate_timings_ms"]["audit_save"] = round((time.perf_counter() - save_started) * 1000, 3)
                self.send_json(result)
            except (KeyError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self.send_error(400, f"bad gate payload: {exc}")
            return
        if parsed.path == "/api/supply-chain/scan":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                scan = scan_component(payload["candidate"], payload.get("baseline"))
                case = scan_to_task_case(scan, task_id=payload.get("task_id", "supply-chain-live-scan"))
                decision = RiskEngine().evaluate(case)
                report = build_audit_report(case, decision)
                report_path = save_report(report, REPORT_DIR)
                self.send_json({
                    "scan": scan,
                    "risk_measurement": asdict(decision),
                    "audit_report_path": str(report_path),
                    "audit_report": report,
                })
            except (KeyError, json.JSONDecodeError, TypeError, ValueError, OSError) as exc:
                self.send_error(400, f"bad supply-chain scan payload: {exc}")
            return
        self.send_error(404, "not found")

    def find_case(self, task_id: str):
        for case in self.load_all_cases():
            if case.task_id == task_id:
                return case
        return None

    def load_all_cases(self):
        return load_case_files([IMPORTED_FILE, DATA_FILE])

    def serve_static(self, request_path: str) -> None:
        if request_path in {"", "/", "/index.html"}:
            self.send_response(302)
            self.send_header("Location", "/security-layer.html")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        rel = request_path.lstrip("/")
        file_path = (FRONTEND / rel).resolve()
        if not str(file_path).startswith(str(FRONTEND.resolve())) or not file_path.exists():
            self.send_error(404, "not found")
            return
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".svg": "image/svg+xml",
        }.get(file_path.suffix, "application/octet-stream")
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if file_path.suffix in {".html", ".css", ".js"}:
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self) -> bool:
        if not SETTINGS.require_auth:
            return True
        bearer = self.headers.get("Authorization", "")
        token = bearer[7:] if bearer.lower().startswith("bearer ") else self.headers.get("X-API-Key", "")
        return hmac.compare_digest(token, SETTINGS.api_token)

    def accepts_gzip(self) -> bool:
        return any(
            part.split(";", 1)[0].strip().lower() == "gzip" and not re.search(r";\s*q=0(?:\.0*)?\s*$", part)
            for part in self.headers.get("Accept-Encoding", "").split(",")
        )

    def send_json(self, payload, status: int = 200, *, etag: str = "") -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=asdict).encode("utf-8")
        compressed = len(body) >= 16384 and self.accepts_gzip()
        if compressed:
            body = gzip.compress(body, compresslevel=1, mtime=0)
        self.send_json_body(body, status, etag=etag, compressed=compressed)

    def send_json_body(self, body: bytes, status: int = 200, *, etag: str = "", compressed: bool = False) -> None:
        if etag and self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Vary", "Accept-Encoding")
        if etag:
            self.send_header("ETag", etag)
        if compressed:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        print(f"[agentmeter] {self.address_string()} - {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((SETTINGS.host, SETTINGS.port), AgentMeterHandler)
    print(f"AgentMeter-Gov server: http://{SETTINGS.host}:{SETTINGS.port} ({SETTINGS.environment})")
    server.serve_forever()


if __name__ == "__main__":
    main()
