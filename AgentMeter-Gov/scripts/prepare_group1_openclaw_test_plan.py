from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "group1_openclaw_cases_v2.json"
OUTPUT_MD = ROOT / "docs" / "GROUP1_OPENCLAW_REAL_TEST_PLAN_V2.md"
OUTPUT_JSON = ROOT / "data" / "group1_openclaw_real_test_plan_v2.json"


def main() -> None:
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    cases = data["cases"]
    priority = sorted(cases, key=priority_key)
    selected = priority[:18]
    plan = {
        "version": "group1-openclaw-real-test-plan-v2",
        "source": str(DATASET),
        "note": "Run these in real local OpenClaw. Do not treat script-only evaluation as final evidence.",
        "cases": [plan_item(case) for case in selected],
    }
    OUTPUT_JSON.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    OUTPUT_MD.write_text(build_md(plan), encoding="utf-8")
    print(f"test_plan_cases={len(selected)}")
    print(f"json={OUTPUT_JSON}")
    print(f"md={OUTPUT_MD}")


def priority_key(case: dict) -> tuple[int, str]:
    severity_rank = {"严重": 0, "高": 1, "中": 2, "低": 3, "无": 4}
    native = 0 if case["native_openclaw_baseline"]["can_execute_or_harmful"] else 1
    return (
        native,
        severity_rank.get(case["labels"]["severity"], 9),
        case["case_id"],
    )


def plan_item(case: dict) -> dict:
    prompt = case["user_prompt"]
    return {
        "case_id": case["case_id"],
        "risk_type": case["risk_type"],
        "risk_type_key": case["risk_type_key"],
        "attack_method": case["attack_method"],
        "severity": case["labels"]["severity"],
        "native_result": case["native_openclaw_baseline"]["actual_result"],
        "expected_agentmeter_action": case["expected_agentmeter_gov"]["action"],
        "openclaw_prompt": prompt,
        "session_key": f"agent:main:group1-v2-{case['case_id'].lower().replace('_','-')}",
        "result_fields_to_fill": {
            "native_rerun_result": "",
            "agentmeter_gov_action": "",
            "agentmeter_gov_score": None,
            "matched_rules": [],
            "audit_report_path": "",
            "pass_or_fail": "",
            "notes": "",
        },
    }


def build_md(plan: dict) -> str:
    lines = [
        "# 第一组 V2.0 真实 OpenClaw 复测计划",
        "",
        "> 这份清单用于第二组真实 OpenClaw 跑测。不要把脚本模拟结果当最终证据。",
        "",
        f"- 数据源：`{plan['source']}`",
        f"- 优先案例数：{len(plan['cases'])}",
        "",
        "## 跑测方法",
        "",
        "1. 关闭 AgentMeter-Gov 防护，复测原生 OpenClaw 表现。",
        "2. 开启 AgentMeter-Gov 防护，使用同一提示词复测。",
        "3. 记录 action、score、matched_rules、audit_report_path。",
        "4. 对漏报和误报回填到规则/BGE 原型库。",
        "",
        "## 优先案例",
        "",
        "| 编号 | 类型 | 方法 | 原生结果 | 危害 | 期望处置 | session_key |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for case in plan["cases"]:
        lines.append(
            f"| {case['case_id']} | {case['risk_type']} | {case['attack_method']} | "
            f"{case['native_result']} | {case['severity']} | {case['expected_agentmeter_action']} | "
            f"`{case['session_key']}` |"
        )
    lines.extend(["", "## OpenClaw 输入样例", ""])
    for case in plan["cases"]:
        lines.extend(
            [
                f"### {case['case_id']} {case['attack_method']}",
                "",
                "```text",
                case["openclaw_prompt"],
                "```",
                "",
            ]
        )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
