from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentmeter_gov.risk_engine import RiskEngine
from agentmeter_gov.schema import TaskCase, ToolEvent


LIBRARY_PATH = ROOT / "data" / "gov_risk_scenario_library_v1.json"
OUT_JSON = ROOT / "data" / "gov_scenario_regression_results.json"
OUT_MD = ROOT / "docs" / "GOV_SCENARIO_REGRESSION_REPORT.md"
ACTION_RANK = {"allow": 0, "human_review": 1, "block": 2}


def main() -> None:
    payload = json.loads(LIBRARY_PATH.read_text(encoding="utf-8"))
    engine = RiskEngine()
    results = []
    for scenario in payload["scenarios"]:
        case = scenario_to_case(scenario)
        decision = engine.evaluate(case)
        expected = str(scenario["expected_action"])
        actual = decision.action
        verdict = compare_actions(expected, actual)
        plan = decision.control_plan
        details = decision.scoring_details
        results.append(
            {
                "id": scenario["id"],
                "category": scenario["category"],
                "title": scenario["title"],
                "expected_action": expected,
                "actual_action": actual,
                "verdict": verdict,
                "score": decision.total_score,
                "risk_level": decision.level,
                "matched_rules": decision.matched_rules,
                "hard_blocks": decision.hard_blocks,
                "control_mode": plan.get("policy_mode"),
                "control_ids": [
                    item.get("control_id")
                    for item in plan.get("controls", [])
                    if isinstance(item, dict) and item.get("control_id")
                ],
                "factor_scores": {item.code: item.score for item in decision.factors},
                "top_factors": top_factors(details),
                "top_contribution_summary": details.get("top_contribution_summary", []),
                "threshold_explanation": details.get("threshold_explanation", {}),
                "risk_focus": scenario.get("risk_focus", []),
            }
        )

    summary = summarize(results)
    report = {
        "report_type": "AgentMeter-Gov government-enterprise scenario regression",
        "library_version": payload.get("version"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        **summary,
        "results": results,
    }
    OUT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    OUT_MD.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ["total", "verdicts", "strict_pass_rate", "safe_pass_rate"]}, ensure_ascii=False, indent=2))
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD)}, ensure_ascii=False))
    if report["verdicts"].get("MISS", 0):
        raise SystemExit(1)


def scenario_to_case(scenario: dict[str, Any]) -> TaskCase:
    input_sources = scenario.get("input_sources") or [
        {
            "name": "OpenClaw user prompt",
            "type": "user",
            "trust": "high",
            "tags": ["user_goal"],
            "content": scenario.get("user_goal", ""),
        }
    ]
    return TaskCase(
        task_id=str(scenario["id"]),
        title=str(scenario["title"]),
        user_goal=str(scenario["user_goal"]),
        input_sources=input_sources,
        events=[event_from_dict(item) for item in scenario["events"]],
        expected_label=str(scenario["expected_action"]),
        user_id=str(scenario.get("user_id", "regression_user")),
    )


def event_from_dict(item: dict[str, Any]) -> ToolEvent:
    return ToolEvent(
        name=str(item["name"]),
        params=dict(item.get("params", {})),
        source=str(item.get("source", "openclaw_before_tool_call")),
        data_level=str(item.get("data_level", "public")),
        result=str(item.get("result", "proposed")),
        evidence=str(item.get("evidence", "scenario regression event")),
    )


def compare_actions(expected: str, actual: str) -> str:
    expected_rank = ACTION_RANK[expected]
    actual_rank = ACTION_RANK[actual]
    if actual_rank < expected_rank:
        return "MISS"
    if actual_rank > expected_rank:
        return "OVERCONTROL"
    return "PASS"


def top_factors(details: dict[str, Any]) -> list[dict[str, Any]]:
    contributions = details.get("factor_contributions", {}) if isinstance(details, dict) else {}
    items = []
    for code, item in contributions.items():
        items.append(
            {
                "code": code,
                "zh_name": item.get("zh_name"),
                "score": item.get("score"),
                "weight": item.get("weight"),
                "contribution": item.get("contribution"),
            }
        )
    return sorted(items, key=lambda item: item.get("contribution") or 0, reverse=True)[:3]


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts = Counter(item["verdict"] for item in results)
    by_category: dict[str, Counter[str]] = defaultdict(Counter)
    for item in results:
        by_category[str(item["category"])][str(item["verdict"])] += 1
    strict_pass = verdicts.get("PASS", 0)
    safe_pass = strict_pass + verdicts.get("OVERCONTROL", 0)
    total = len(results)
    return {
        "verdicts": dict(verdicts),
        "by_category": {key: dict(value) for key, value in sorted(by_category.items())},
        "strict_pass_rate": round(strict_pass / total, 3) if total else 0,
        "safe_pass_rate": round(safe_pass / total, 3) if total else 0,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# AgentMeter-Gov 政企风险场景回归报告",
        "",
        f"- 生成时间：{report['generated_at']}",
        f"- 样本总数：{report['total']}",
        f"- 严格通过率：{report['strict_pass_rate']}",
        f"- 安全通过率：{report['safe_pass_rate']}（PASS + OVERCONTROL；MISS 视为必须修复）",
        f"- 结果统计：{json.dumps(report['verdicts'], ensure_ascii=False)}",
        "",
        "| ID | 类别 | 预期 | 实际 | 分数 | 结论 | 主要因子 | 命中规则 |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for item in report["results"]:
        top = ", ".join(
            f"{factor['code']}={factor['score']}({factor['contribution']})"
            for factor in item["top_factors"]
        )
        rules = "<br>".join(str(rule) for rule in item["matched_rules"][:3])
        lines.append(
            f"| {item['id']} | {item['category']} | {item['expected_action']} | "
            f"{item['actual_action']} | {item['score']} | {item['verdict']} | {top} | {rules} |"
        )

    misses = [item for item in report["results"] if item["verdict"] == "MISS"]
    overcontrols = [item for item in report["results"] if item["verdict"] == "OVERCONTROL"]
    lines.extend(["", "## 需要处理的问题", ""])
    if not misses and not overcontrols:
        lines.append("- 本轮没有 MISS 或 OVERCONTROL。")
    if misses:
        lines.append("### MISS")
        for item in misses:
            lines.append(f"- {item['id']}：预期 {item['expected_action']}，实际 {item['actual_action']}，需要增强防护。")
    if overcontrols:
        lines.append("### OVERCONTROL")
        for item in overcontrols:
            lines.append(f"- {item['id']}：预期 {item['expected_action']}，实际 {item['actual_action']}，需要检查是否误报。")
    lines.extend(
        [
            "",
            "## 使用说明",
            "",
            "- `PASS`：实际处置与预期一致。",
            "- `MISS`：实际处置弱于预期，属于安全漏防，必须优先修复。",
            "- `OVERCONTROL`：实际处置强于预期，属于潜在误报，需要结合真实 OpenClaw 复测决定是否收敛。",
        ]
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
