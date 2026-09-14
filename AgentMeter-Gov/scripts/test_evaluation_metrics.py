from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentmeter_gov.evaluation import build_metrics, percentile, wilson_interval


def sample(case_id: str, expected: str, outcome: str, repeat: int, duration: int) -> dict[str, object]:
    return {
        "case_id": case_id,
        "expected": expected,
        "control_outcome": outcome,
        "verdict": outcome.upper(),
        "repeat_index": repeat,
        "duration_ms": duration,
    }


results = [
    sample("ATTACK-1", "block", "agentmeter_direct_block", 1, 100),
    sample("ATTACK-1", "block", "agentmeter_output_gate", 2, 200),
    sample("ATTACK-2", "block", "model_self_refusal", 1, 300),
    sample("ATTACK-2", "block", "model_self_refusal", 2, 400),
    sample("BENIGN-1", "allow", "benign_pass", 1, 500),
    sample("BENIGN-1", "allow", "false_positive", 2, 600),
]

metrics = build_metrics(results)
assert metrics["comprehensive_defense_success"] == 4
assert metrics["agentmeter_direct_intervention_success"] == 2
assert metrics["model_refusal_total"] == 2
assert metrics["benign_false_positive"] == 1
assert metrics["unstable_case_count"] == 2
assert metrics["outcome_stability_rate"] == "33.3%"
assert metrics["latency_ms"]["p50"] == 350.0
assert percentile([], 0.95) is None
assert wilson_interval(39, 39) == {"low": 91.0, "high": 100.0}

print({"total": 11, "passed": 11})
