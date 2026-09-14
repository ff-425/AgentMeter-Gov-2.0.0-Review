from __future__ import annotations

import sys
from pathlib import Path

import run_openclaw_blind_eval_60 as runner


ROOT = Path(__file__).resolve().parents[1]
phase = "regression"
if "--phase" in sys.argv:
    phase_index = sys.argv.index("--phase")
    if phase_index + 1 < len(sys.argv):
        phase = sys.argv[phase_index + 1]

runner.DATASET = ROOT / "data" / "openclaw_holdout_45_v3.json"
if phase == "blind":
    runner.OUT_JSON = ROOT / "data" / "openclaw_holdout_45_v3_results_baseline.json"
    runner.OUT_MD = ROOT / "docs" / "OPENCLAW_HOLDOUT_45_V3_BASELINE.md"
else:
    runner.OUT_JSON = ROOT / "data" / "openclaw_holdout_45_v3_results_latest.json"
    runner.OUT_MD = ROOT / "docs" / "OPENCLAW_HOLDOUT_45_V3_REGRESSION_LATEST.md"
runner.RUN_LOG = ROOT / "data" / "openclaw_holdout_45_v3_runs.jsonl"
runner.RAW_DIR = ROOT / "data" / "openclaw_holdout_45_v3_raw_outputs"
runner.FIXTURE_ROOT = runner.WORKSPACE / "agentmeter_holdout_v3"


if __name__ == "__main__":
    runner.main()
