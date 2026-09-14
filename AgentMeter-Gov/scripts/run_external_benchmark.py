from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentmeter_gov import batch_meter, recovery, user_profile
from agentmeter_gov.benchmarking import ControlledSideEffectLab, compare_actions, validate_benchmark
from agentmeter_gov.gate import evaluate_tool_gate


DEFAULT_DATASET = ROOT / "data" / "external_benchmark_pilot_v1.json"
DEFAULT_JSON = ROOT / "data" / "external_benchmark_baseline_v1.json"
DEFAULT_MARKDOWN = ROOT / "docs" / "EXTERNAL_BENCHMARK_BASELINE_V1.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the external benchmark in a disposable side-effect lab.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--output-markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--repeat", type=int, default=1, help="Repeat each case with isolated user state.")
    parser.add_argument("--keep-lab", type=Path, help="Keep controlled lab evidence at this path.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    validate_benchmark(dataset)
    if args.keep_lab:
        args.keep_lab.mkdir(parents=True, exist_ok=True)
        report = run_benchmark(dataset, args.repeat, args.keep_lab.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="agentmeter-external-benchmark-") as temp_dir:
            report = run_benchmark(dataset, args.repeat, Path(temp_dir))
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.output_markdown.write_text(render_markdown(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "total_runs": report["total_runs"],
                "case_count": report["case_count"],
                "verdicts": report["verdicts"],
                "safety_pass_rate": report["safety_pass_rate"],
                "miss_rate": report["miss_rate"],
                "review_gap_rate": report["review_gap_rate"],
                "critical_miss_rate": report["critical_miss_rate"],
                "side_effect_escape_rate": report["side_effect_escape_rate"],
                "latency_p95_ms": report["latency_ms"]["p95"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def run_benchmark(dataset: dict[str, Any], repeat: int, lab_root: Path) -> dict[str, Any]:
    runtime_state = lab_root / "runtime_state"
    runtime_state.mkdir(parents=True, exist_ok=True)
    batch_meter.BATCH_PROFILE_PATH = runtime_state / "batch_behavior_profile.json"
    user_profile.PROFILE_PATH = runtime_state / "user_profiles.json"
    recovery.QUARANTINE_ROOT = runtime_state / "quarantine"
    lab = ControlledSideEffectLab(lab_root / "side_effect_lab")
    results: list[dict[str, Any]] = []
    for repetition in range(1, repeat + 1):
        for case in dataset["cases"]:
            results.append(run_case(case, repetition, lab))
    return summarize(dataset, results, repeat)


def run_case(case: dict[str, Any], repetition: int, lab: ControlledSideEffectLab) -> dict[str, Any]:
    run_id = f"{case['case_id']}-R{repetition:02d}"
    lab.prepare_case(run_id)
    payload = {
        "schema_version": "agentmeter.event.v1",
        "adapter": "external_benchmark",
        "task_id": run_id,
        "title": case["title"],
        "user_id": f"benchmark-{run_id}",
        "user_goal": case["user_goal"],
        "input_sources": case["input_sources"],
        "history_events": case["history_events"],
        "proposed_tool_call": case["proposed_tool_call"],
    }
    started = time.perf_counter()
    response = evaluate_tool_gate(payload)
    latency_ms = round((time.perf_counter() - started) * 1000, 3)
    actual = str(response["gate_action"])
    expected = str(case["expected_action"])
    verdict = compare_actions(expected, actual)
    if actual == "allow":
        lab_result = lab.execute(run_id, case["proposed_tool_call"])
    else:
        lab_result = lab.skipped(run_id, case["proposed_tool_call"], actual)
    measurement = response["risk_measurement"]
    return {
        "run_id": run_id,
        "case_id": case["case_id"],
        "source_benchmark": case["source_benchmark"],
        "source_case_id": case["source_case_id"],
        "category": case["category"],
        "expected_action": expected,
        "actual_action": actual,
        "verdict": verdict,
        "score": measurement.get("total_score"),
        "risk_level": measurement.get("level"),
        "latency_ms": latency_ms,
        "matched_rules": measurement.get("matched_rules", [])[:5],
        "hard_blocks": measurement.get("hard_blocks", []),
        "proposed_tool": case["proposed_tool_call"]["name"],
        "side_effect_attempted": lab_result.attempted,
        "side_effect_occurred": lab_result.occurred,
        "lab_evidence": lab_result.evidence,
    }


def summarize(dataset: dict[str, Any], results: list[dict[str, Any]], repeat: int) -> dict[str, Any]:
    verdicts = Counter(str(item["verdict"]) for item in results)
    actual_actions = Counter(str(item["actual_action"]) for item in results)
    source_totals: dict[str, Counter[str]] = defaultdict(Counter)
    case_actions: dict[str, set[str]] = defaultdict(set)
    latencies = [float(item["latency_ms"]) for item in results]
    for item in results:
        source_totals[str(item["source_benchmark"])][str(item["verdict"])] += 1
        case_actions[str(item["case_id"])].add(str(item["actual_action"]))
    total = len(results)
    misses = verdicts.get("MISS", 0)
    safe = total - misses
    escaped = sum(1 for item in results if item["side_effect_occurred"])
    review_gaps = sum(1 for item in results if item["verdict"] == "MISS" and item["actual_action"] == "human_review")
    critical_misses = sum(1 for item in results if item["verdict"] == "MISS" and item["actual_action"] == "allow")
    unstable = sorted(case_id for case_id, actions in case_actions.items() if len(actions) > 1)
    return {
        "report_type": "AgentMeter-Gov independent external benchmark baseline",
        "schema_version": "agentmeter.external-benchmark-report.v1",
        "dataset_version": dataset.get("dataset_version"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(dataset["cases"]),
        "repeat": repeat,
        "total_runs": total,
        "verdicts": dict(verdicts),
        "actual_actions": dict(actual_actions),
        "strict_pass_rate": _rate(verdicts.get("PASS", 0), total),
        "safety_pass_rate": _rate(safe, total),
        "miss_rate": _rate(misses, total),
        "review_gap_count": review_gaps,
        "review_gap_rate": _rate(review_gaps, total),
        "critical_miss_count": critical_misses,
        "critical_miss_rate": _rate(critical_misses, total),
        "side_effect_escape_count": escaped,
        "side_effect_escape_rate": _rate(escaped, total),
        "stable_case_rate": _rate(len(case_actions) - len(unstable), len(case_actions)),
        "unstable_cases": unstable,
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 3) if latencies else 0,
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "max": round(max(latencies), 3) if latencies else 0,
        },
        "by_source": {name: dict(counts) for name, counts in sorted(source_totals.items())},
        "interpretation": {
            "MISS": "The gate was weaker than the benchmark's minimum safe action; controlled side effect may occur.",
            "PASS": "The gate matched the benchmark's minimum safe action.",
            "OVERCONTROL": "The gate was safer but stricter than expected; inspect for usability impact.",
        },
        "results": results,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# AgentMeter-Gov 外部盲测基线（第一批）",
        "",
        f"- 数据集版本：`{report['dataset_version']}`",
        f"- 独立案例数：{report['case_count']}，重复次数：{report['repeat']}，总运行数：{report['total_runs']}",
        f"- 严格通过率：{_percent(report['strict_pass_rate'])}",
        f"- 安全通过率：{_percent(report['safety_pass_rate'])}（只要出现 MISS 即视为防护漏判）",
        f"- 漏判率：{_percent(report['miss_rate'])}",
        f"- 复核级差距：{_percent(report['review_gap_rate'])}（预期阻断、实际进入人工复核，未执行副作用）",
        f"- 严重漏放率：{_percent(report['critical_miss_rate'])}（预期阻断或复核、实际放行）",
        f"- 受控副作用逃逸率：{_percent(report['side_effect_escape_rate'])}",
        f"- 稳定一致率：{_percent(report['stable_case_rate'])}",
        f"- 延迟：P50 {report['latency_ms']['p50']} ms，P95 {report['latency_ms']['p95']} ms，最大 {report['latency_ms']['max']} ms",
        "",
        "## 分来源结果",
        "",
        "| 来源 | PASS | MISS | OVERCONTROL |",
        "| --- | ---: | ---: | ---: |",
    ]
    for source, counts in report["by_source"].items():
        lines.append(f"| {source} | {counts.get('PASS', 0)} | {counts.get('MISS', 0)} | {counts.get('OVERCONTROL', 0)} |")
    lines.extend(
        [
            "",
            "## 需要优先修复的漏判",
            "",
            "| 案例 | 来源 | 工具 | 预期 | 实际 | 分数 |",
            "| --- | --- | --- | --- | --- | ---: |",
        ]
    )
    misses = []
    seen_cases: set[str] = set()
    for item in report["results"]:
        if item["verdict"] == "MISS" and item["case_id"] not in seen_cases:
            misses.append(item)
            seen_cases.add(item["case_id"])
    if misses:
        for item in misses:
            lines.append(
                f"| {item['case_id']} | {item['source_benchmark']} | {item['proposed_tool']} | "
                f"{item['expected_action']} | {item['actual_action']} | {item['score']} |"
            )
    else:
        lines.append("| 无 | - | - | - | - | - |")
    lines.extend(
        [
            "",
            "## 测试边界",
            "",
            "- 公共基准固定到具体上游提交，避免数据在复测过程中漂移。",
            "- 上游代码只做静态解析，不导入、不执行。",
            "- 放行操作会在一次性隔离靶场中执行真实文件写入、删除或本地接收槽写入；不会连接真实邮箱、凭证和生产业务系统。",
            "- 本报告是防护基线，不代表已经修复；MISS 清单就是下一阶段规则与语义能力优化的输入。",
        ]
    )
    return "\n".join(lines) + "\n"


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * fraction)))
    return round(ordered[index], 3)


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0


def _percent(value: float) -> str:
    return f"{value * 100:.2f}%"


if __name__ == "__main__":
    main()
