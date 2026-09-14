"""Normalize legacy OpenClaw JSONL evidence without inventing missing facts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from live_eval_contract import strongest_action


def normalize(row: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    item = dict(row)
    issues: list[str] = []
    actions = [str(value) for value in item.get("gate_actions", [])]
    original_action = str(item.get("agentmeter_action") or item.get("actual_action") or "")
    candidates = [*actions]
    if original_action in {"allow", "human_review", "block"}:
        candidates.append(original_action)
    agentmeter_action = strongest_action(candidates)
    if original_action and agentmeter_action and original_action != agentmeter_action:
        issues.append(f"aggregate corrected: {original_action} -> {agentmeter_action}")
    item["agentmeter_action"] = agentmeter_action
    item["actual_action"] = agentmeter_action or original_action
    resisted = bool(item.get("model_resisted"))
    item["model_outcome"] = "resisted" if resisted else (
        "complied_harmfully" if item.get("unsafe_side_effect") else "unknown"
    )
    item["agentmeter_enforced"] = agentmeter_action in {"block", "human_review"}

    raw = item.get("_raw") if isinstance(item.get("_raw"), dict) else {}
    model_ms = raw.get("_meta", {}).get("durationMs") if isinstance(raw.get("_meta"), dict) else None
    total_ms = item.get("duration_ms")
    gate_ms = [float(value) for value in item.get("gate_latency_ms", []) if isinstance(value, (int, float))]
    item["timings"] = {
        "end_to_end_ms": total_ms,
        "openclaw_model_ms": model_ms,
        "agentmeter_gate_total_ms": round(sum(gate_ms), 3),
        "runner_and_collection_overhead_ms": (
            round(max(0.0, float(total_ms) - float(model_ms)), 3)
            if isinstance(total_ms, (int, float)) and isinstance(model_ms, (int, float)) else None
        ),
    }
    for field in ("audit_id", "max_risk_score", "rule_ids"):
        if item.get(field) in (None, "", []):
            issues.append(f"missing {field}; rerun required")
    item["evidence_complete"] = not any(problem.startswith("missing ") for problem in issues)
    item["normalization_issues"] = issues
    return item, issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    normalized: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []
    for row in rows:
        item, issues = normalize(row)
        normalized.append(item)
        if issues:
            problems.append({"case_id": item.get("case_id", ""), "issues": issues})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in normalized), encoding="utf-8")
    report = {
        "total": len(normalized),
        "aggregate_corrections": sum(any("aggregate corrected" in issue for issue in row["issues"]) for row in problems),
        "evidence_complete": sum(bool(row["evidence_complete"]) for row in normalized),
        "model_and_agentmeter_separated": len(normalized),
        "problems": problems,
    }
    report_path = args.report or args.output.with_suffix(".validation.json")
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "problems"}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
