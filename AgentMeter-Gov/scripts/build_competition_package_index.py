from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
OUT = ROOT / "docs" / "COMPETITION_PACKAGE_INDEX.md"

MATERIALS = [
    ("1.0 系统架构", "docs/ARCHITECTURE.md"),
    ("1.1.1 发布清单", "../docs/RELEASE_CHECKLIST_1.1.1.md"),
    ("1.1.1 演示手册", "../docs/DEMO_RUNBOOK_1.1.1.md"),
    ("比赛标准流程", "AgentMeter-Gov/docs/COMPETITION_STANDARD_WORKFLOW_V1.md"),
    ("比赛交付物清单", "AgentMeter-Gov/docs/COMPETITION_DELIVERABLE_CHECKLIST_V1.md"),
    ("风险计量模型 V2", "AgentMeter-Gov/docs/RISK_METERING_MODEL_V2.md"),
    ("风险计量规则 V2.1", "AgentMeter-Gov/docs/RISK_MEASUREMENT_RULE_SYSTEM_V2_1.md"),
    ("风险样本矩阵", "AgentMeter-Gov/docs/RISK_SAMPLE_MATRIX_V1.md"),
    ("政企场景回归报告", "AgentMeter-Gov/docs/GOV_SCENARIO_REGRESSION_REPORT.md"),
    ("73 样本评测报告", "AgentMeter-Gov/docs/REALISTIC_GOV_TEST_EVAL_REPORT.md"),
    ("红队攻击套件报告", "AgentMeter-Gov/docs/REDTEAM_ATTACK_SUITE_REPORT.md"),
    ("安全防护测试报告", "AgentMeter-Gov/docs/SECURITY_DEFENSE_TEST_REPORT.md"),
    ("最新 OpenClaw 全量实测", "AgentMeter-Gov/docs/GROUP1_FULL_OPENCLAW_LIVE_RESULTS_LATEST.md"),
    ("1.0 三动作真机闭环", "AgentMeter-Gov/docs/GROUP1_FULL_OPENCLAW_LIVE_RESULTS_SUBSET_A1-01_A1-04_BEN-02_LATEST.md"),
    ("输出闸门验证", "AgentMeter-Gov/docs/OUTPUT_GATE_VALIDATION_20260816.md"),
    ("审计案例包", "AgentMeter-Gov/docs/OPENCLAW_AUDIT_CASEBOOK_V1.md"),
]

SCRIPTS = [
    ("固定闭环案例", "AgentMeter-Gov/scripts/run_demo.py"),
    ("50 场景回归", "AgentMeter-Gov/scripts/run_gov_scenario_regression.py"),
    ("73 样本评测", "AgentMeter-Gov/scripts/run_realistic_gov_dataset_eval.py"),
    ("30 例红队套件", "AgentMeter-Gov/scripts/run_redteam_attack_suite.py"),
    ("安全防护测试", "AgentMeter-Gov/scripts/run_security_defense_tests.py"),
    ("全量 OpenClaw 实测", "AgentMeter-Gov/scripts/run_group1_full_openclaw_live.py"),
]


def main() -> None:
    metrics = {
        "50 场景回归": metric("data/gov_scenario_regression_results.json", "total", "verdicts"),
        "73 样本评测": metric("data/realistic_gov_test_eval_results.json", "total", "verdicts"),
        "30 例红队套件": metric("data/redteam_attack_suite_results.json", "total", "verdicts"),
        "安全防护测试": defense_metric(),
    }
    lines = [
        "# AgentMeter-Gov 1.0 比赛材料索引",
        "",
        f"- 生成时间：`{datetime.now(timezone.utc).isoformat()}`",
        "- 产品版本：`1.1.1`",
        "- 定位：面向 OpenClaw 政企场景的全链路风险计量、安全处置与审计系统。",
        "",
        "## 当前自动评测",
        "",
    ]
    lines.extend(f"- {label}：{value}" for label, value in metrics.items())
    lines.extend(["", "## 核心材料", "", "| 材料 | 路径 | 状态 |", "| --- | --- | --- |"])
    for label, rel in MATERIALS:
        lines.append(f"| {label} | `{rel}` | {'ready' if (REPO_ROOT / rel).exists() else 'missing'} |")
    lines.extend(["", "## 可复现实验脚本", "", "| 脚本 | 路径 | 状态 |", "| --- | --- | --- |"])
    for label, rel in SCRIPTS:
        lines.append(f"| {label} | `{rel}` | {'ready' if (REPO_ROOT / rel).exists() else 'missing'} |")
    lines.extend([
        "",
        "## 推荐复现顺序",
        "",
        "1. 在仓库根目录运行 `scripts/verify_release.ps1 -CheckOpenClaw`。",
        "2. 启动 `python AgentMeter-Gov/server.py` 并打开监控页。",
        "3. 运行固定案例和输出脱敏演示。",
        "4. 按需运行 50/73/30 样本评测。",
        "5. 真实 OpenClaw 演示时使用 `run_group1_full_openclaw_live.py --cases ...` 限定案例。",
    ])
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"markdown": str(OUT)}, ensure_ascii=False))


def metric(rel: str, total_key: str, verdict_key: str) -> str:
    payload = read_json(ROOT / rel)
    total = payload.get(total_key, 0)
    verdicts = payload.get(verdict_key, {})
    passed = verdicts.get("PASS", 0)
    return f"{passed}/{total} PASS"


def defense_metric() -> str:
    payload = read_json(ROOT / "data/security_defense_test_results.json")
    return f"{payload.get('passed', 0)}/{payload.get('total', 0)} PASS"


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
