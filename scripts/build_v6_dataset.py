"""Build the V6 government-enterprise security evaluation corpus.

V6 extends the frozen V5 corpus with the ADR-303 government-enterprise task
set (261 benign business tasks + 42 malicious tasks, 17 threat techniques).
The V5 partitions are already normalized, deduplicated and labeled, so this
builder re-imports the frozen V5 cases, adds normalized ADR-303 cases, removes
any cross-source duplicates, and re-partitions into fresh development,
regression, and sealed-blind splits. The sealed partition is never copied into
the source repository.

Rationale: V5's own report recommended a V6 isolated set that broadens benign
business coverage (false-positive measurement) and gate coverage. ADR-303 is a
realistic government-enterprise MCP task set that fits exactly that gap.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

# Reuse the proven V5 primitives verbatim.
from build_v5_dataset import (  # noqa: E402
    SCHEMA,
    assign_partitions,
    canonical_text,
    deduplicate,
    distribution,
    make_case,
    sha256_bytes,
    stratified_select,
    write_jsonl,
)

try:
    import openpyxl  # noqa: E402
except ImportError as exc:  # pragma: no cover
    raise SystemExit("openpyxl is required: pip install openpyxl") from exc


V6_PREFIX = {"development": "DEV", "regression": "REG", "blind": "BLIND"}


def reindex_partitions(partitions: dict[str, list[dict[str, Any]]]) -> None:
    """Re-stamp partition case ids with the V6 label after re-partitioning."""
    for partition, values in partitions.items():
        for index, case in enumerate(values, 1):
            case["case_id"] = f"V6-{V6_PREFIX[partition]}-{index:03d}"


def load_frozen_v5(v5_root: Path) -> list[dict[str, Any]]:
    files = {
        "development": v5_root / "01_开发集" / "v5_development.jsonl",
        "regression": v5_root / "02_回归集" / "v5_regression.jsonl",
        "blind": v5_root / "03_密封盲测集" / "v5_blind.jsonl",
    }
    cases: list[dict[str, Any]] = []
    for path in files.values():
        if not path.is_file():
            raise FileNotFoundError(path)
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            case = json.loads(line)
            # Drop the V5 partition assignment; V6 re-partitions from scratch.
            case.pop("partition", None)
            case["case_id"] = ""
            cases.append(case)
    return cases


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def load_adr303(path: Path) -> list[dict[str, Any]]:
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.worksheets[0]
    rows = list(ws.iter_rows(min_row=1, values_only=True))
    header = [_clean(c) for c in rows[0]]
    idx = {name: header.index(name) for name in header}

    def col(row: tuple[Any, ...], name: str) -> str:
        return _clean(row[idx[name]]) if name in idx and idx[name] < len(row) else ""

    cases: list[dict[str, Any]] = []
    for row in rows[1:]:
        if row is None or all(c is None for c in row):
            continue
        task_id = col(row, "task_id")
        if not task_id:
            continue
        ground_truth = col(row, "ground_truth").lower()
        label = "benign" if ground_truth == "benign" else "attack"
        threat = col(row, "threat_technique")
        scenario = col(row, "需求场景")
        description = col(row, "description")
        high_risk = col(row, "AgentMeter_Gov高危筛选").lower() == "true"
        severity = "high" if (label == "attack" and high_risk) else ("high" if label == "attack" else "low")
        cases.append(
            make_case(
                source="adr-303",
                original_id=task_id,
                label=label,
                category=" ".join([threat, scenario, description]),
                severity=severity,
                prompt=col(row, "user_prompt"),
                attack_goal=threat or description,
                checkpoint="mcp_tool_guard",
                source_expected="block" if (label == "attack" and high_risk) else "",
                source_metadata={
                    "description": description,
                    "scenario": scenario,
                    "mcp_servers": col(row, "mcp_servers"),
                    "expected_tools": col(row, "expected_tools"),
                    "validation_method": col(row, "validation_method"),
                    "threat_technique": threat,
                    "high_risk_flag": high_risk,
                },
            )
        )
    return cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v5-root", required=True, type=Path, help="Frozen V5 dataset root")
    parser.add_argument("--adr303", required=True, type=Path, help="ADR-303 xlsx")
    parser.add_argument("--output", required=True, type=Path, help="V6 dataset root")
    args = parser.parse_args()

    frozen = load_frozen_v5(args.v5_root)
    adr = load_adr303(args.adr303)
    loaded = frozen + adr
    unique, duplicates = deduplicate(loaded)
    partitions = assign_partitions(unique)
    reindex_partitions(partitions)

    live_counts = {"development": 30, "regression": 22, "blind": 22}

    root = args.output.resolve()
    paths = {
        "development": root / "01_开发集",
        "regression": root / "02_回归集",
        "blind": root / "03_密封盲测集",
    }
    for name, cases in partitions.items():
        write_jsonl(paths[name] / f"v6_{name}.jsonl", cases)
        write_jsonl(
            paths[name] / f"v6_{name}_live_selected.jsonl",
            stratified_select(cases, min(live_counts[name], len(cases))),
        )

    inventory = {
        "schema_version": SCHEMA,
        "dataset_version": "v6",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "frozen_v5": {"path": str(args.v5_root.resolve()), "case_count": len(frozen)},
            "adr-303": {
                "path": str(args.adr303.resolve()),
                "sha256": sha256_bytes(args.adr303.read_bytes()),
                "case_count": len(adr),
            },
        },
        "loaded_total": len(loaded),
        "deduplicated_total": len(unique),
        "removed_duplicates": len(duplicates),
        "overall": distribution(unique),
        "partitions": {name: distribution(cases) for name, cases in partitions.items()},
        "live_selected": {
            name: distribution(stratified_select(cases, min(live_counts[name], len(cases))))
            for name, cases in partitions.items()
        },
    }
    (root / "00_清单").mkdir(parents=True, exist_ok=True)
    (root / "00_清单" / "source_inventory.json").write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (root / "00_清单" / "dedup_report.json").write_text(
        json.dumps(duplicates, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    blind_file = paths["blind"] / "v6_blind.jsonl"
    blind_live = paths["blind"] / "v6_blind_live_selected.jsonl"
    seal = {
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(partitions["blind"]),
        "full_sha256": sha256_bytes(blind_file.read_bytes()),
        "live_selected_count": min(live_counts["blind"], len(partitions["blind"])),
        "live_selected_sha256": sha256_bytes(blind_live.read_bytes()),
        "rule": "Do not inspect or execute until development fixes and regression validation are frozen.",
    }
    (paths["blind"] / "SEAL.json").write_text(
        json.dumps(seal, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    card = "# AgentMeter-Gov V6 政企安全评测集\n\n"
    card += "在冻结的 V5 语料基础上，新增 ADR-303 政企任务集（真实 MCP 业务任务，含大量正常业务用于误报测量）。\n\n"
    card += f"- 合并原始案例：{len(loaded)} 条（V5 {len(frozen)} + ADR-303 {len(adr)}）\n"
    card += f"- 去重后：{len(unique)} 条\n- 去除重复：{len(duplicates)} 条\n"
    card += f"- 开发集：{len(partitions['development'])} 条\n- 回归集：{len(partitions['regression'])} 条\n- 密封盲测集：{len(partitions['blind'])} 条\n"
    card += f"- 真实 OpenClaw 首轮选择：开发 {live_counts['development']} 条、回归 {live_counts['regression']} 条、盲测 {live_counts['blind']} 条\n\n"
    card += "盲测集在开发修复与回归结果冻结前不得查看。所有真实执行只允许访问每个案例的一次性目录，不得使用真实凭证、真实邮箱或外部服务。\n"
    (root / "V6_数据集说明.md").write_text(card, encoding="utf-8")

    print(json.dumps(inventory, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
