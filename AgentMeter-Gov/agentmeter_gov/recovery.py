from __future__ import annotations

import os
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import TaskCase, ToolEvent


PROJECT_ROOT = Path(__file__).resolve().parents[1]
QUARANTINE_ROOT = PROJECT_ROOT / "data" / "quarantine"
STAGING_MARKERS = ("outbox", "export", "exports", "tmp", "temp", "upload", "uploads", "queue", "staged")
SENSITIVE_LEVELS = {"internal_sensitive", "secret", "confidential"}


@dataclass
class RecoveryPlan:
    version: str
    required: bool
    mode: str
    blocked_action: str
    related_prior_actions: list[dict[str, Any]]
    compensation_steps: list[dict[str, Any]]
    non_reversible_effects: list[dict[str, Any]]
    rationale: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_recovery_plan(
    *,
    case: TaskCase,
    action: str,
    blocked_events: list[str],
    taint_summary: dict[str, object],
    batch_analysis: dict[str, Any] | None = None,
) -> RecoveryPlan:
    current = case.events[-1] if case.events else None
    prior_events = case.events[:-1] if current else case.events
    related: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    non_reversible: list[dict[str, Any]] = []
    rationale: list[str] = []

    if action not in {"block", "human_review"}:
        return RecoveryPlan(
            version="recovery-plan-v1",
            required=False,
            mode="none",
            blocked_action=current.name if current else "",
            related_prior_actions=[],
            compensation_steps=[],
            non_reversible_effects=[],
            rationale=["当前动作未被阻断或复核，不生成补偿计划。"],
        )

    taint_level = str(taint_summary.get("taint_level", "none"))
    current_inherits_taint = bool(taint_summary.get("current_inherits_taint"))
    batch_split = bool((batch_analysis or {}).get("split_operation_suspected"))
    blocked_action = current.name if current else ",".join(blocked_events)

    for index, event in enumerate(prior_events, 1):
        role = _risk_role(event)
        if role == "none":
            continue
        if role in {"staging_write", "official_mutation", "audit_side_effect"} or current_inherits_taint or batch_split:
            related.append(_event_ref(index, event, role))

    for item in related:
        role = str(item.get("risk_role", ""))
        target = str(item.get("target", ""))
        if role == "staging_write":
            steps.append(
                {
                    "step_id": f"COMP-{len(steps) + 1:02d}",
                    "type": "quarantine_file",
                    "target": target,
                    "auto_execute": action == "block",
                    "reason": "前序中转文件可能承载内部/敏感数据，后续动作已被阻断或复核。",
                }
            )
        elif role == "official_mutation":
            steps.append(
                {
                    "step_id": f"COMP-{len(steps) + 1:02d}",
                    "type": "restore_from_snapshot_or_diff_review",
                    "target": target,
                    "auto_execute": False,
                    "reason": "正式文件或审批状态曾发生写入，需依据快照/差异人工确认是否恢复。",
                }
            )
        elif role == "audit_side_effect":
            steps.append(
                {
                    "step_id": f"COMP-{len(steps) + 1:02d}",
                    "type": "preserve_audit_copy",
                    "target": target,
                    "auto_execute": action == "block",
                    "reason": "审计相关文件出现副作用，需保护原始证据并禁止覆盖。",
                }
            )

    if current and current.name in {"send_email", "upload_file", "submit_approval", "approve_request"}:
        non_reversible.append(
            {
                "action": current.name,
                "target": _event_target(current),
                "reason": "该动作一旦执行通常无法可靠撤销，因此必须以前置阻断/复核为主。",
            }
        )
    if current and current.name in {"delete_file", "delete_audit_log"}:
        non_reversible.append(
            {
                "action": current.name,
                "target": _event_target(current),
                "reason": "删除/清空类动作可能破坏原始证据，应执行前硬阻断。",
            }
        )

    if current_inherits_taint:
        rationale.append(f"当前动作继承前序 {taint_level} 污染，需要沿执行图向前追溯。")
    if batch_split:
        rationale.append("批量计量模块判断存在拆分操作嫌疑，需要补偿前序中转或副作用。")
    if not rationale and blocked_events:
        rationale.append("当前动作被阻断，生成最小补偿检查计划。")

    mode = "manual_compensation_required" if steps else "preventive_block_only"
    return RecoveryPlan(
        version="recovery-plan-v1",
        required=bool(steps or non_reversible),
        mode=mode,
        blocked_action=blocked_action,
        related_prior_actions=related,
        compensation_steps=steps,
        non_reversible_effects=non_reversible,
        rationale=rationale,
    )


def execute_recovery_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Execute bounded compensation steps.

    Only file quarantine/copy steps inside approved local roots are automated.
    Formal document rollback and business-system actions remain manual.
    """

    steps = plan.get("compensation_steps", []) if isinstance(plan, dict) else []
    if not isinstance(steps, list) or not steps:
        return {
            "version": "recovery-execution-v1",
            "executed": False,
            "results": [],
            "reason": "no compensation steps",
        }

    batch_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        if not step.get("auto_execute"):
            results.append({
                "step_id": step.get("step_id", ""),
                "status": "manual_required",
                "reason": "step is not marked auto_execute",
            })
            continue
        step_type = str(step.get("type", ""))
        target = str(step.get("target", ""))
        if step_type == "quarantine_file":
            results.append(_quarantine_file(step, target, batch_id))
        elif step_type == "preserve_audit_copy":
            results.append(_preserve_copy(step, target, batch_id))
        else:
            results.append({
                "step_id": step.get("step_id", ""),
                "status": "manual_required",
                "target": target,
                "reason": f"{step_type} is not safe for automatic execution",
            })

    return {
        "version": "recovery-execution-v1",
        "executed": any(item.get("status") in {"quarantined", "copied"} for item in results),
        "results": results,
    }


def _risk_role(event: ToolEvent) -> str:
    text = _event_text(event)
    if event.name in {"write_file", "apply_patch", "run_shell"} and any(marker in text for marker in STAGING_MARKERS):
        return "staging_write"
    if event.name in {"modify_official_document", "submit_approval", "approve_request"}:
        return "official_mutation"
    if any(marker in text for marker in ["审批", "验收", "合同", "公文", "approval", "contract"]) and any(
        marker in text for marker in ["修改", "改为", "改成", "replace", "newtext", "approved", "submit"]
    ):
        return "official_mutation"
    if event.name in {"delete_audit_log"} or any(marker in text for marker in ["audit.log", "access.log", "error.log", "审计", "日志"]):
        if event.name in {"write_file", "apply_patch", "run_shell", "delete_audit_log", "delete_file"}:
            return "audit_side_effect"
    if event.data_level in SENSITIVE_LEVELS and event.name in {"write_file", "apply_patch", "run_shell"}:
        return "staging_write"
    return "none"


def _event_ref(index: int, event: ToolEvent, role: str) -> dict[str, Any]:
    return {
        "index": index,
        "action": event.name,
        "target": _event_target(event),
        "data_level": event.data_level,
        "risk_role": role,
        "result": event.result,
    }


def _event_target(event: ToolEvent) -> str:
    for key in ("path", "file", "target", "to", "url", "destination", "attachment"):
        value = event.params.get(key)
        if value:
            return str(value).replace("\\", "/")
    return _extract_redirect_target(str(event.params.get("command", "")))


def _event_text(event: ToolEvent) -> str:
    return f"{event.name} {event.params} {event.evidence}".lower().replace("\\", "/")


def _extract_redirect_target(command: str) -> str:
    text = str(command or "")
    for marker in (">>", ">"):
        if marker in text:
            return text.split(marker, 1)[1].strip().strip("\"' ")
    return ""


def _quarantine_file(step: dict[str, Any], target: str, batch_id: str) -> dict[str, Any]:
    source = _resolve_existing_file(target)
    if source is None:
        return {
            "step_id": step.get("step_id", ""),
            "status": "skipped",
            "target": target,
            "reason": "target file does not exist inside approved recovery roots",
        }
    destination = _quarantine_destination(source, batch_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    return {
        "step_id": step.get("step_id", ""),
        "status": "quarantined",
        "source": str(source),
        "destination": str(destination),
        "reason": step.get("reason", ""),
    }


def _preserve_copy(step: dict[str, Any], target: str, batch_id: str) -> dict[str, Any]:
    source = _resolve_existing_file(target)
    if source is None:
        return {
            "step_id": step.get("step_id", ""),
            "status": "skipped",
            "target": target,
            "reason": "target file does not exist inside approved recovery roots",
        }
    destination = _quarantine_destination(source, batch_id, suffix=".preserved")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(source), str(destination))
    return {
        "step_id": step.get("step_id", ""),
        "status": "copied",
        "source": str(source),
        "destination": str(destination),
        "reason": step.get("reason", ""),
    }


def _quarantine_destination(source: Path, batch_id: str, suffix: str = "") -> Path:
    safe_name = str(source).replace(":", "").replace("\\", "/").strip("/")
    return QUARANTINE_ROOT / batch_id / f"{safe_name}{suffix}"


def _resolve_existing_file(target: str) -> Path | None:
    if not target:
        return None
    roots = _approved_roots()
    raw = Path(target.replace("\\", "/"))
    candidates: list[Path] = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.extend(root / raw for root in roots)
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not resolved.exists() or not resolved.is_file():
            continue
        if any(_is_relative_to(resolved, root) for root in roots):
            return resolved
    return None


def _approved_roots() -> list[Path]:
    roots = [PROJECT_ROOT, PROJECT_ROOT.parent, Path.cwd()]
    openclaw_workspace = Path.home() / ".openclaw" / "workspace" / "main"
    roots.append(openclaw_workspace)
    configured = os.environ.get("AGENTMETER_RECOVERY_ROOTS", "")
    for item in configured.split(os.pathsep):
        if item.strip():
            roots.append(Path(item.strip()))
    approved: list[Path] = []
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            continue
        if resolved not in approved:
            approved.append(resolved)
    return approved


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
