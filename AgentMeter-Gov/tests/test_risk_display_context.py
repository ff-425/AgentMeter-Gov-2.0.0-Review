from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from dataclasses import asdict
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@contextmanager
def isolated_server():
    # The dashboard import initializes storage; isolate it even for fixture export.
    with tempfile.TemporaryDirectory(prefix="agentmeter-risk-display-") as directory, patch.dict(os.environ, {
        "AGENTMETER_DATABASE_URL": "sqlite:///" + str(Path(directory) / "events.db"),
        "AGENTMETER_FLOW_LOG": str(Path(directory) / "events.jsonl"),
        "AGENTMETER_REQUIRE_AUTH": "false",
    }):
        import server
        yield server


def display_fixtures(server):
    from agentmeter_gov.risk_engine import RiskEngine
    from agentmeter_gov.schema import TaskCase, ToolEvent

    fixtures = {}
    for key, goal, level in (
        ("public", "把本周工作周报发给 wangjl@abc-tech.com，正文仅包含公开进度。", "public"),
        ("unnamed", "把本周工作周报发给材料中的联系人，正文仅包含公开进度。", "public"),
        ("sensitive", "把人员名单发给 wangjl@abc-tech.com。", "internal_sensitive"),
    ):
        tool = ToolEvent(name="send_email", source="before_tool_call", data_level=level, result="proposed", params={
            "path": "outbox/reply.md", "content": "收件邮箱：wangjl@abc-tech.com\n本周公开项目进度汇总。",
            "agentmeter_raw_tool_name": "write",
        })
        case = TaskCase(task_id=key, title=key, user_goal=goal, input_sources=[], events=[tool])
        decision = RiskEngine().evaluate(case)
        payload = {
            "task_id": key, "event_type": "pending_review_event", "adapter": "merge-test",
            "timestamp": "2026-09-09T10:00:00Z", "review_id": "AGR-" + key,
            "tool_name": tool.name, "proposed_tool_call": asdict(tool),
            "gate_action": decision.action, "risk_score": decision.total_score,
            "triggered_rules": decision.matched_rules, "user_goal": goal,
        }
        fixtures[key] = server.redact_for_dashboard(server.slim_event(payload))
    return fixtures


class RiskDisplayContextTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        context = isolated_server()
        cls.server = context.__enter__()
        cls.addClassCleanup(context.__exit__, None, None, None)

    def test_real_engine_provenance_and_sensitive_evidence(self):
        fixtures = display_fixtures(self.server)
        self.assertEqual(fixtures["public"]["risk_score"], 40)
        self.assertEqual(fixtures["public"]["gate_action"], "human_review")
        for key, rule in (("public", "R-03A"), ("unnamed", "R-03B"), ("sensitive", "R-02")):
            with self.subTest(key=key):
                event = fixtures[key]
                self.assertTrue(any(item.startswith(rule) for item in event["triggered_rules"]))
                self.assertEqual(event["recipients"], ["wa***@abc-tech.com"])
                self.assertNotIn("wangjl@", json.dumps(event))
                self.assertEqual(event["target"], "outbox/reply.md")

    def test_structured_recipients_win_and_intranet_is_masked(self):
        event = self.server.slim_event({"tool_name": "send_email", "parameters": {
            "to": "alice@internal", "cc": "bob@example.org", "bcc": ["carol@example.org"],
            "content": "收件邮箱：ignored@example.org",
        }})
        self.assertEqual(event["recipients"], ["al***@internal", "bo***@example.org", "ca***@example.org"])

    def test_non_outbound_and_legacy_records_do_not_invent_recipients(self):
        for event in ({}, {"tool_name": "read", "parameters": {"content": "收件邮箱：alice@example.org"}}):
            self.assertEqual(self.server.slim_event(event)["recipients"], [])

    def test_invalid_parameter_container_is_still_rejected(self):
        with self.assertRaises(ValueError):
            self.server.slim_event({"tool_name": "send_email", "parameters": []})


if __name__ == "__main__":
    if "--fixtures" in sys.argv:
        with isolated_server() as server:
            print(json.dumps(display_fixtures(server), ensure_ascii=False))
    else:
        unittest.main()
