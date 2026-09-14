from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentmeter_gov.audit import build_audit_report, save_report
from agentmeter_gov.risk_engine import RiskEngine
from agentmeter_gov.supply_chain import scan_component, scan_to_task_case


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan OpenClaw Skill/plugin supply-chain drift.")
    parser.add_argument("--baseline", required=True, help="Trusted baseline Skill/plugin directory.")
    parser.add_argument("--candidate", required=True, help="Candidate Skill/plugin directory.")
    parser.add_argument("--task-id", default="supply-chain-skill-drift-001")
    parser.add_argument("--out-json", default=str(ROOT / "data" / "supply_chain_skill_drift_result.json"))
    parser.add_argument("--out-md", default=str(ROOT / "docs" / "SUPPLY_CHAIN_SKILL_DRIFT_REPORT.md"))
    args = parser.parse_args()

    scan = scan_component(args.candidate, args.baseline)
    case = scan_to_task_case(scan, task_id=args.task_id)
    decision = RiskEngine().evaluate(case)
    report = build_audit_report(case, decision)
    report_path = save_report(report, ROOT / "audit_reports")

    result = {
        "scan": scan,
        "risk_decision": asdict(decision),
        "audit_report": str(report_path),
    }
    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(_render_markdown(result), encoding="utf-8")

    print(json.dumps({
        "action": decision.action,
        "score": decision.total_score,
        "matched_rules": decision.matched_rules,
        "scan_json": str(out_json),
        "scan_report": str(out_md),
        "audit_report": str(report_path),
    }, ensure_ascii=False, indent=2))


def _render_markdown(result: dict[str, object]) -> str:
    scan = result["scan"]
    decision = result["risk_decision"]
    component = scan["component"]
    baseline = scan["baseline_component"]
    evidence_rows = [
        f"| {item['capability']} | `{item['file']}:{item['line']}` | {item['pattern']} | `{item['snippet']}` |"
        for item in scan.get("evidence", [])
    ]
    if not evidence_rows:
        evidence_rows = ["| none | none | none | none |"]

    return "\n".join([
        "# AgentMeter-Gov Supply-Chain Drift Scan",
        "",
        "## Component",
        "",
        f"- Baseline: `{baseline.get('name', '')}` `{baseline.get('version', '')}`",
        f"- Candidate: `{component.get('name', '')}` `{component.get('version', '')}`",
        f"- Scanner recommendation: `{scan['recommendation']}`",
        f"- Scanner risk score: `{scan['risk_score']}`",
        f"- AgentMeter-Gov action: `{decision['action']}`",
        f"- AgentMeter-Gov total score: `{decision['total_score']}`",
        "",
        "## Capability Diff",
        "",
        f"- Declared capabilities: `{', '.join(scan.get('declared_capabilities', []))}`",
        f"- Observed capabilities: `{', '.join(scan.get('observed_capabilities', []))}`",
        f"- Added high-risk capabilities: `{', '.join(scan.get('high_risk_added_capabilities', []))}`",
        f"- Undeclared high-risk capabilities: `{', '.join(scan.get('high_risk_undeclared_capabilities', []))}`",
        f"- Drift flags: `{', '.join(scan.get('drift_flags', []))}`",
        "",
        "## Matched Rules",
        "",
        *[f"- {rule}" for rule in decision.get("matched_rules", [])],
        "",
        "## Evidence",
        "",
        "| Capability | Location | Pattern | Snippet |",
        "| --- | --- | --- | --- |",
        *evidence_rows,
        "",
    ])


if __name__ == "__main__":
    main()
