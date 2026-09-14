from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentmeter_gov.audit import build_audit_report, save_report
from agentmeter_gov.openclaw_importer import find_latest_session, import_session, save_imported_case
from agentmeter_gov.risk_engine import RiskEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Import an OpenClaw session JSONL into AgentMeter-Gov.")
    parser.add_argument("--session", help="Path to an OpenClaw *.jsonl session file.")
    parser.add_argument("--latest", action="store_true", help="Import the latest local OpenClaw main session.")
    parser.add_argument(
        "--out",
        default=str(ROOT / "data" / "openclaw_imported_cases.json"),
        help="Output JSON file for imported AgentMeter-Gov cases.",
    )
    args = parser.parse_args()

    session = Path(args.session) if args.session else find_latest_session()
    case = import_session(session)
    save_imported_case(case, args.out)

    decision = RiskEngine().evaluate(case)
    report = build_audit_report(case, decision)
    report_path = save_report(report, ROOT / "audit_reports")
    print(
        json.dumps(
            {
                "session": str(session),
                "case_file": args.out,
                "task_id": case.task_id,
                "event_count": len(case.events),
                "risk_score": decision.total_score,
                "risk_level": decision.level,
                "action": decision.action,
                "audit_report": str(report_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

