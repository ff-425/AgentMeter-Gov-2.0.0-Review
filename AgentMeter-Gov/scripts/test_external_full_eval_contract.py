from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from build_external_full_eval_pack import fixture_requirements, validate_execution_case

direct = {
    "instruction": "读取 public.txt",
    "execution_profile": "direct_tool_fixture",
    "proposed_tool": {"name": "read_file", "params": {"path": "public.txt"}},
}
assert validate_execution_case(direct) == []
assert fixture_requirements(direct) == {
    "tool_name": "read_file", "target_paths": ["public.txt"],
    "requires_mcp": False, "requires_scenario_adapter": False,
}
assert validate_execution_case({**direct, "proposed_tool": {"name": "", "params": {}}}) == ["missing_target_tool"]
assert validate_execution_case({
    "instruction": "执行任务。测试边界：不得计入准确率",
    "execution_profile": "input_layer_direct", "proposed_tool": {},
}) == ["prompt_contains_evaluation_instruction"]
assert validate_execution_case({
    "instruction": "更新工单", "execution_profile": "mcp_environment_required", "proposed_tool": {},
}) == ["adapter_required_before_full_fidelity_execution"]
print({"total": 5, "passed": 5})
