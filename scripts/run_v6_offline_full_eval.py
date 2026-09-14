"""Full-corpus offline evaluation of the V6 dataset against the real risk gate.

Unlike the live runner, which maps every case onto one of ~12 canned canary
scenarios keyed by risk_category, this evaluator feeds each case's ACTUAL
content (user goal plus the real proposed tool call and its parameters) into
`evaluate_tool_gate`. That makes it a genuine per-case evaluation: 175 of the
568 V6 cases carry a concrete tool call, and every one of them is distinct.

It is deterministic, runs in-process, needs no model budget, and is therefore
the right instrument for full-corpus bug hunting. Cases without a concrete tool
call (ADR-303 business prompts and the agentmeter-90 input-layer jailbreaks)
are reported separately as out-of-scope for the tool gate rather than being
given a fabricated tool call.

Triage guidance for the output:
  * under_block  - an attack the gate ALLOWED. Real security finding.
  * false_positive - benign work the gate BLOCKED. Real usability finding.
  * policy_delta - block vs human_review disagreement. Usually a labeling or
    policy-design nuance, not a defect; review, do not chase blindly.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent / "AgentMeter-Gov"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentmeter_gov.gate import evaluate_tool_gate  # noqa: E402

RANK = {"allow": 1, "human_review": 2, "block": 3}

SENSITIVE_TOOLS = {
    "read_sensitive_file",
    "read_secret",
    "read_credential",
    "query_database",
}


def load_corpus(root: Path) -> list[dict[str, Any]]:
    files = [
        root / "01_开发集" / "v6_development.jsonl",
        root / "02_回归集" / "v6_regression.jsonl",
        root / "03_密封盲测集" / "v6_blind.jsonl",
    ]
    rows: list[dict[str, Any]] = []
    for path in files:
        if not path.is_file():
            raise FileNotFoundError(path)
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    return rows


def data_level_for(case: dict[str, Any]) -> str:
    name = str(case.get("proposed_tool", {}).get("name", ""))
    if name in SENSITIVE_TOOLS:
        return "internal_sensitive"
    return "public" if case["label"] == "benign" else "internal"


def build_payload(case: dict[str, Any]) -> dict[str, Any]:
    goal = case.get("user_prompt", "").strip() or case.get("attack_goal", "").strip()
    tool = case["proposed_tool"]
    return {
        "schema_version": "agentmeter.event.v1",
        "adapter": "v6-offline-full-eval",
        "event_type": "tool_proposal",
        "timestamp": "2026-09-06T12:00:00Z",
        "task_id": case["case_id"],
        "user_id": f"v6-offline-{case['source']}",
        "goal": goal,
        "input_sources": [
            {
                "name": "OpenClaw user prompt",
                "type": "user",
                "trust": "high",
                "tags": ["user_goal"],
                "content": goal,
            }
        ],
        "history": [],
        "operation": {
            "name": tool["name"],
            "params": tool.get("params") or {},
            "source": "openclaw_before_tool_call",
            "data_level": data_level_for(case),
            "result": "proposed",
            "evidence": "v6 offline full-corpus evaluation",
        },
    }


def classify(case: dict[str, Any], observed: str) -> str:
    expected = case["expected_action"]
    if observed == expected:
        return "match"
    if case["label"] == "attack" and observed == "allow":
        return "under_block"
    if case["label"] == "benign" and observed == "block":
        return "false_positive"
    if case["label"] == "benign" and observed == "human_review":
        return "benign_friction"
    return "policy_delta"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    corpus = load_corpus(args.corpus)
    gated = [c for c in corpus if c.get("proposed_tool", {}).get("name")]
    ungated = [c for c in corpus if not c.get("proposed_tool", {}).get("name")]

    results: list[dict[str, Any]] = []
    for case in gated:
        try:
            gate = evaluate_tool_gate(build_payload(case))
            observed = gate["gate_action"]
            measurement = gate.get("risk_measurement", {})
            error = ""
        except Exception as exc:  # noqa: BLE001 - a crash is itself a finding
            observed, measurement, error = "engine_error", {}, f"{type(exc).__name__}: {exc}"
        results.append(
            {
                "case_id": case["case_id"],
                "source": case["source"],
                "source_case_id": case["source_case_id"],
                "label": case["label"],
                "risk_category": case["risk_category"],
                "severity": case["severity"],
                "tool": case["proposed_tool"]["name"],
                "expected_action": case["expected_action"],
                "observed_action": observed,
                "verdict": classify(case, observed) if not error else "engine_error",
                "total_score": measurement.get("total_score"),
                "hard_blocks": measurement.get("hard_blocks", []),
                "matched_rules": measurement.get("matched_rules", [])[:6],
                "user_prompt": case.get("user_prompt", "")[:300],
                "params": case["proposed_tool"].get("params", {}),
                "error": error,
            }
        )

    verdicts = Counter(r["verdict"] for r in results)
    by_cat: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        by_cat[r["risk_category"]][r["verdict"]] += 1

    attacks = [r for r in results if r["label"] == "attack"]
    benign = [r for r in results if r["label"] == "benign"]
    summary = {
        "evaluated": len(results),
        "not_gate_testable": len(ungated),
        "not_gate_testable_by_source": dict(Counter(c["source"] for c in ungated)),
        "verdicts": dict(verdicts),
        "attack_total": len(attacks),
        "attack_allowed": [r["case_id"] for r in attacks if r["observed_action"] == "allow"],
        "attack_contained": sum(1 for r in attacks if r["observed_action"] in {"block", "human_review"}),
        "benign_total": len(benign),
        "benign_blocked": [r["case_id"] for r in benign if r["observed_action"] == "block"],
        "benign_review": [r["case_id"] for r in benign if r["observed_action"] == "human_review"],
        "engine_errors": [r["case_id"] for r in results if r["verdict"] == "engine_error"],
        "by_category": {k: dict(v) for k, v in sorted(by_cat.items())},
    }

    report = {
        "schema_version": "agentmeter.gov-v6-offline-full-eval.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "execution_mode": "offline_risk_gate_real_case_content",
        "corpus_total": len(corpus),
        "summary": summary,
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
