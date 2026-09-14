from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from analyze_external_live_results import markdown_report, percentile, summarize


truth = [
    {"case_id": "A", "label": "attack", "expected_action": "block", "evaluation_dimensions": ["执行安全"]},
    {"case_id": "B", "label": "attack", "expected_action": "human_review", "evaluation_dimensions": ["数据安全"]},
    {"case_id": "C", "label": "benign", "expected_action": "allow", "evaluation_dimensions": ["执行安全"]},
    {"case_id": "D", "label": "benign", "expected_action": "allow", "evaluation_dimensions": ["内容安全"]},
]
common = {
    "run_status": "completed", "execution_fidelity": "full", "backend_unavailable": False,
    "audit_complete": True, "audit_id": "AUD", "max_risk_score": 50,
    "rule_ids": ["R-1"], "approval_count": 0, "duplicate_approval_count": 0,
    "end_to_end_latency_ms": 1000, "guard_latency_ms": 12,
}
results = [
    {**common, "case_id": "A", "agentmeter_action": "block", "agentmeter_enforced": True},
    {**common, "case_id": "B", "agentmeter_action": "human_review", "agentmeter_enforced": True, "approval_count": 1},
    {**common, "case_id": "C", "agentmeter_action": "allow"},
    {**common, "case_id": "D", "agentmeter_action": "human_review", "approval_count": 2, "duplicate_approval_count": 1},
]
report = summarize(results, truth)
summary = report["summary"]
assert summary["completion_rate"] == 1.0
assert summary["infrastructure_valid_rate"] == 1.0
assert summary["attack_containment_rate"] == 1.0
assert summary["agentmeter_attack_interception_rate"] == 1.0
assert summary["benign_false_positive_rate"] == 0.5
assert summary["three_class_accuracy"] == 0.75
assert summary["duplicate_approval_rate"] == 0.5
assert summary["audit_complete_rate"] == 1.0
assert summary["confusion_matrix"]["allow"]["human_review"] == 1
assert summary["failure_attribution"]["benign_false_positive"]["case_ids"] == ["D"]
assert percentile([1, 2, 3, 4, 100], 0.99) == 96.16
rendered = markdown_report(report)
assert "良性误报率：50.00%" in rendered
assert "P99=" in rendered

print({"total": 14, "passed": 14})
