from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agentmeter_gov.review_state import reconcile_reviews, task_status


class ReviewMonitoringTest(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)

    def event(self, kind, second, **fields):
        return {"event_type": kind, "timestamp": (self.now + timedelta(seconds=second)).isoformat(),
                "task_id": "original", "session_key": "session-a", **fields}

    def request(self, identifier="AGR-ONE", second=1, path="a.txt", **fields):
        return self.event("pending_review_event", second, review_id=identifier,
                          proposed_tool_call={"name": "read", "params": {"path": path}}, **fields)

    def resolve(self, decision="approve", identifier="AGR-ONE", second=2, **fields):
        return self.event("approval_event", second, review_id=identifier,
                          review_decision=decision, approval_id="APP-GRANT", **fields)

    def state(self, events, replies=()):
        reviews = reconcile_reviews({"original": events, "reply": list(replies)})["original"]
        return task_status(events, reviews), reviews

    def test_rejection_closes_the_original_task_even_from_a_reply_task(self):
        status, reviews = self.state([self.request()], [self.resolve("reject", task_id="reply")])
        self.assertEqual(status, "review_rejected")
        self.assertEqual(reviews[0]["state"], "rejected")

    def test_approval_is_not_execution_and_only_resolves_its_request(self):
        events = [self.request(), self.resolve()]
        self.assertEqual(self.state(events)[0], "approved_awaiting_retry")
        events.append(self.event("risk_decision_event", 3, gate_action="human_review_approved", review_id="AGR-ONE", approval_id="APP-GRANT"))
        events.append(self.request("AGR-TWO", 4, "b.txt"))
        status, reviews = self.state(events)
        self.assertEqual(status, "awaiting_review")
        self.assertEqual([(r["review_id"], r["state"]) for r in reviews], [("AGR-ONE", "released"), ("AGR-TWO", "pending")])

    def test_pending_operation_survives_a_different_blocked_operation(self):
        events = [self.event("risk_decision_event", 0, gate_action="block", tool_name="read", target="a.txt"), self.request(path="b.txt")]
        self.assertEqual(self.state(events)[0], "awaiting_review")

    def test_decision_and_pending_pair_in_either_order_and_retries_do_not_reopen(self):
        decision = self.event("risk_decision_event", 1, gate_action="human_review", tool_name="read", parameters={"path": "a.txt"})
        pending = self.request(second=1)
        for events in ([decision, pending], [pending, decision]):
            with self.subTest(first=events[0]["event_type"]):
                status, reviews = self.state([*events, self.resolve("reject"), self.request(second=3)])
                self.assertEqual(status, "review_rejected")
                self.assertEqual(len(reviews), 1)

    def test_repeated_decision_reuses_the_existing_review_without_orphans(self):
        def decision(second):
            return self.event("risk_decision_event", second, gate_action="human_review", proposed_tool_call={"name": "read", "params": {"path": "a.txt"}})
        events = [decision(0), self.request(), decision(2), self.request(second=3), self.resolve("reject", second=4)]
        status, reviews = self.state(events)
        self.assertEqual(status, "review_rejected")
        self.assertEqual(len(reviews), 1)

    def test_equivalent_tool_aliases_pair_one_review_request(self):
        params = {"path": "a.txt"}
        pending = self.event("pending_review_event", 1, review_id="AGR-ONE", tool_name="write_file",
                             proposed_tool_call={"name": "write_file", "params": params}, parameters=params)
        decision = self.event("risk_decision_event", 1, gate_action="human_review", tool_name="write",
                              proposed_tool_call={"name": "write_file", "params": params}, parameters=params)
        status, reviews = self.state([pending, decision])
        self.assertEqual(status, "awaiting_review")
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["review_id"], "AGR-ONE")

    def test_unknown_or_wrong_session_approvals_do_not_hide_pending(self):
        replies = [self.resolve(identifier="AGR-OTHER"), self.resolve(session_key="session-b"),
                   self.resolve(approval_scope="no_pending_review")]
        self.assertEqual(self.state([self.request()], replies)[0], "awaiting_review")

    def test_ambiguous_review_id_does_not_resolve_two_tasks(self):
        groups = {"original": [self.request()], "other": [self.request(task_id="other")], "reply": [self.resolve()]}
        states = reconcile_reviews(groups)
        self.assertEqual(states["original"][0]["state"], "pending")
        self.assertEqual(states["other"][0]["state"], "pending")

    def test_legacy_request_id_and_idless_release_keep_new_requests_pending(self):
        legacy = self.request(identifier="", approval_id="AGR-ONE")
        self.assertEqual(self.state([legacy, self.resolve("reject")])[0], "review_rejected")
        decision = self.event("risk_decision_event", 1, gate_action="human_review", tool_name="read", parameters={"path": "a.txt"})
        release = self.event("risk_decision_event", 2, gate_action="human_review_approved", tool_name="read", parameters={"path": "a.txt"})
        status, reviews = self.state([decision, release, self.request("AGR-TWO", 3, "b.txt")])
        self.assertEqual(status, "awaiting_review")
        self.assertEqual([r["state"] for r in reviews], ["released", "pending"])

    def test_result_pending_is_not_task_completion(self):
        self.assertEqual(self.state([self.event("result_event", 1, status="pending")])[0], "running")

    def test_grant_id_release_completes_only_after_approval_and_result(self):
        release = self.event("risk_decision_event", 3, gate_action="human_review_approved", approval_id="APP-GRANT", task_id="reply")
        events = [self.request(), self.event("result_event", 4, status="completed")]
        status, reviews = self.state(events, [self.resolve(task_id="reply"), release])
        self.assertEqual(status, "completed")
        self.assertEqual(reviews[0]["state"], "released")

    def test_task_history_exposes_resolved_state_and_pending_counts(self):
        with tempfile.TemporaryDirectory(prefix="agentmeter-review-test-") as directory:
            with patch.dict(os.environ, {"AGENTMETER_DATABASE_URL": "sqlite:///" + str(Path(directory) / "events.db")}):
                import server
            events = [self.event("input_event", 0, user_goal="Read two files"), self.request(),
                      self.resolve("reject", task_id="reply"), self.request("AGR-TWO", 3, "b.txt")]
            with patch.object(server, "read_live_events", return_value=events):
                result = server.build_task_history(task_limit=1)
            self.assertEqual(result["task_count"], 1)
            task = result["tasks"][0]
            self.assertEqual(task["status"], "awaiting_review")
            self.assertEqual(task["review_count"], 2)
            self.assertEqual(task["pending_review_count"], 1)
            self.assertEqual([review["state"] for review in task["reviews"]], ["rejected", "pending"])
            self.assertFalse(any(event["event_type"] == "approval_event" for event in task["events"]))


if __name__ == "__main__":
    unittest.main()
