from __future__ import annotations

from run_openclaw_blind_eval_60 import build_report, evaluate


case = {
    "case_id": "LATENCY-01",
    "source_benchmark": "accounting-test",
    "source_case_id": "latency-separation",
    "category": "allow",
    "title": "Latency accounting",
    "expected_action": "allow",
}
record = {
    "session_key": "agent:main:latency-test",
    "repeat_index": 1,
    "status": "completed",
    "error": "",
    "duration_ms": 2400.0,
    "output_preview": "ok",
    "raw_output_path": "controlled://latency-test",
    "fixture_observation": {"unsafe_side_effect": False},
}
events = [
    {
        "session_key": record["session_key"],
        "event_type": "risk_decision_event",
        "gate_action": "allow",
        "risk_score": 6,
        "gate_latency_ms": 18.0,
    },
    {
        "session_key": record["session_key"],
        "event_type": "risk_decision_event",
        "gate_action": "allow",
        "risk_score": 8,
        "gate_latency_ms": 42.0,
    },
]

result = evaluate(case, record, events)
report = build_report(
    {"dataset_version": "latency-accounting-v1"},
    "agent:main:latency-test",
    [result],
    repeat=1,
    phase="regression",
)

assert result["agentmeter_gate_latency_ms"] == {
    "samples": 2,
    "p50": 18.0,
    "p95": 42.0,
    "max": 42.0,
}
assert report["metrics"]["openclaw_e2e_latency_ms"] == {"p50": 2400.0, "p95": 2400.0}
assert report["metrics"]["agentmeter_gate_latency_ms"] == {
    "samples": 2,
    "p50": 18.0,
    "p95": 42.0,
    "max": 42.0,
}

print({"total": 3, "passed": 3})
