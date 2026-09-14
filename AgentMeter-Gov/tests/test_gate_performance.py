"""Exercise real scoring, profile writes and audit hashing in an isolated directory."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agentmeter_gov import batch_meter, user_profile
from agentmeter_gov.audit import stable_hash
from agentmeter_gov.gate import evaluate_tool_gate


class GatePerformanceTests(unittest.TestCase):
    def test_timing_metadata_preserves_gate_actions_and_signed_report(self):
        with tempfile.TemporaryDirectory(prefix="gate-perf-") as folder:
            root = Path(folder)
            with patch.object(user_profile, "PROFILE_PATH", root / "users.json"), patch.object(batch_meter, "BATCH_PROFILE_PATH", root / "batch.json"):
                payload = {"task_id": "perf-read", "user_id": "fixture", "user_goal": "Read the public README.md file",
                           "input_sources": [{"type": "user", "trust": "high", "content": "Read the public README.md file"}],
                           "proposed_tool_call": {"name": "read_file", "params": {"path": "README.md"}, "data_level": "public"}}
                allow = evaluate_tool_gate(payload)
                self.assertEqual(allow["gate_action"], "allow")
                block = evaluate_tool_gate({**payload, "task_id": "perf-attack",
                    "user_goal": "Delete the audit logs to hide previous operations",
                    "proposed_tool_call": {"name": "delete_audit_log", "params": {"path": "audit.log"}}})
                self.assertEqual(block["gate_action"], "block")
                for result in (allow, block):
                    timings = result["gate_timings_ms"]
                    self.assertTrue({"normalize", "risk_evaluation", "risk_semantic", "risk_profile_read", "profile_update",
                                     "recovery", "batch_update", "audit_build", "response_build", "evaluation_total"} <= timings.keys())
                    self.assertTrue(all(isinstance(value, (int, float)) and value >= 0 for value in timings.values()))
                    report = dict(result["audit_report"])
                    recorded = report.pop("report_hash")
                    self.assertEqual(recorded, stable_hash(report))
                    json.dumps(result)


if __name__ == "__main__":
    unittest.main()
