from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentmeter_gov.audit import build_audit_report, save_report
from agentmeter_gov.case_loader import load_cases
from agentmeter_gov.risk_engine import RiskEngine


def main() -> None:
    cases = load_cases(ROOT / "data" / "demo_cases.json")
    engine = RiskEngine()
    results = []
    for case in cases:
        decision = engine.evaluate(case)
        expected_action = {
            "demo-pdf-leak-001": "block",
            "demo-normal-001": "allow",
            "demo-skill-drift-001": "block",
            "demo-human-review-001": "human_review",
        }.get(case.task_id)
        if expected_action and decision.action != expected_action:
            raise SystemExit(
                f"{case.task_id}: expected {expected_action}, observed {decision.action}"
            )
        report = build_audit_report(case, decision)
        report_path = save_report(report, ROOT / "audit_reports")
        results.append(
            {
                "task_id": case.task_id,
                "title": case.title,
                "score": decision.total_score,
                "level": decision.level,
                "action": decision.action,
                "report": str(report_path),
            }
        )
    observed_actions = {item["action"] for item in results}
    required_actions = {"allow", "human_review", "block"}
    if not required_actions.issubset(observed_actions):
        raise SystemExit(
            f"demo does not cover all release actions: {sorted(observed_actions)}"
        )
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
