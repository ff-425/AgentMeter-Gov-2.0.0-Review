from __future__ import annotations

from pathlib import Path

import run_openclaw_blind_eval_60 as runner


ROOT = Path(__file__).resolve().parents[1]
runner.DATASET = ROOT / "data" / "openclaw_holdout_60_v2.json"
runner.OUT_JSON = ROOT / "data" / "openclaw_holdout_60_v2_results_latest.json"
runner.OUT_MD = ROOT / "docs" / "OPENCLAW_HOLDOUT_60_V2_REGRESSION_LATEST.md"
runner.RUN_LOG = ROOT / "data" / "openclaw_holdout_60_v2_runs.jsonl"
runner.RAW_DIR = ROOT / "data" / "openclaw_holdout_60_v2_raw_outputs"
runner.FIXTURE_ROOT = runner.WORKSPACE / "agentmeter_holdout_v2"


if __name__ == "__main__":
    runner.main()
