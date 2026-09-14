from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class InvalidMonitoringEventsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="agentmeter-invalid-events-")
        cls.database = Path(cls.directory.name) / "events.db"
        cls.flow_log = Path(cls.directory.name) / "events.jsonl"
        cls.environment = patch.dict(os.environ, {
            "AGENTMETER_DATABASE_URL": "sqlite:///" + str(cls.database),
            "AGENTMETER_FLOW_LOG": str(cls.flow_log),
            "AGENTMETER_REQUIRE_AUTH": "false",
        })
        cls.environment.start()
        import server
        cls.server = server
        cls.boot = datetime.now(timezone.utc) - timedelta(minutes=10)
        cls.clock = patch.object(server, "monitoring_boot_started_at", return_value=cls.boot)
        cls.clock.start()
        cls.sources = patch.object(server, "FLOW_LOGS", (cls.flow_log,))
        cls.sources.start()
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.AgentMeterHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.httpd.server_address[1])
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        cls.sources.stop()
        cls.clock.stop()
        cls.environment.stop()
        cls.directory.cleanup()

    def setUp(self):
        # This SQLite file belongs solely to the temporary test server.
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM audit_events")
        self.flow_log.write_text("", encoding="utf-8")
        self.server._LIVE_EVENT_CACHE["expires_at"] = 0

    def request(self, path, payload=None, *, post=False):
        data = json.dumps(payload).encode("utf-8") if post else None
        request = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def add_valid_task(self):
        payload = {"event_type": "input_event", "adapter": "openclaw", "task_id": "valid-task", "user_goal": "valid monitoring task"}
        status, response = self.request("/api/events", payload, post=True)
        self.assertEqual(status, 201, response)

    def assert_monitoring_available(self, expected_ignored=0, expected_unbounded_ignored=None):
        routes = (
            "/api/live/tasks?scope=current", "/api/health?scope=current",
            "/api/live/summary?scope=current", "/api/live/events",
        )
        for route in routes:
            with self.subTest(route=route):
                status, response = self.request(route)
                self.assertEqual(status, 200, response)
                route_expected = expected_unbounded_ignored if route == "/api/live/events" and expected_unbounded_ignored is not None else expected_ignored
                self.assertEqual(response["data_quality"]["ignored_record_count"], route_expected)
                self.assertEqual(response["data_quality"]["status"], "partial" if route_expected else "complete")
                self.assertNotIn("DO_NOT_EXPOSE_BAD_PAYLOAD", json.dumps(response))
                if "tasks" in response:
                    self.assertEqual([task["task_id"] for task in response["tasks"]], ["valid-task"])

    def test_api_rejects_invalid_shapes_without_persisting_or_breaking_reads(self):
        self.add_valid_task()
        invalid_fields = (
            {"proposed_tool_call": "DO_NOT_EXPOSE_BAD_PAYLOAD"},
            {"proposed_tool_call": {"params": ["unexpected"]}},
            {"security_control": ["unexpected"]},
            {"security_control": {"controls": 3}},
            {"scoring_details": "unexpected"},
            {"scoring_details": {"recovery_plan": []}},
            {"parameters": []}, {"gate_action": []}, {"event_type": {}},
            {"timestamp": "not-an-iso-date"}, {"risk_score": float("nan")},
            {"parameters": {"limit": float("inf")}},
            {"evidence": {"value": float("nan")}},
            {"evidence": "\ud800"},
            {"task_id": []}, {"review_id": {}}, {"triggered_rules": "unexpected"},
        )
        payloads = [None, [], "DO_NOT_EXPOSE_BAD_PAYLOAD"] + [
            {"event_type": "risk_decision_event", "adapter": "openclaw", **fields}
            for fields in invalid_fields
        ]
        for payload in payloads:
            with self.subTest(payload_type=type(payload).__name__):
                status, response = self.request("/api/events", payload, post=True)
                self.assertEqual(status, 400, response)
                self.assertNotIn("DO_NOT_EXPOSE_BAD_PAYLOAD", json.dumps(response))
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM audit_events").fetchone()[0], 1)
        self.assert_monitoring_available()

    def test_invalid_legacy_database_and_jsonl_records_are_isolated_and_preserved(self):
        self.add_valid_task()
        old = (self.boot - timedelta(days=1)).isoformat()
        malformed = {"event_type": "risk_decision_event", "timestamp": old, "proposed_tool_call": "DO_NOT_EXPOSE_BAD_PAYLOAD"}
        legacy_payloads = [json.dumps(malformed), "[]", "{DO_NOT_EXPOSE_BAD_PAYLOAD", '{"value":' + "9" * 5000 + '}',
                           json.dumps({"event_type": "input_event", "timestamp": old, "evidence": "\ud800"})]
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.executemany(
                "INSERT INTO audit_events(event_id,timestamp,event_type,payload,previous_signature,signature) VALUES(?,?,?,?,?,?)",
                [("legacy-" + str(index), old, "risk_decision_event", payload, "", "") for index, payload in enumerate(legacy_payloads)],
            )
        original_log = '\nnull\n[]\n"DO_NOT_EXPOSE_BAD_PAYLOAD"\n{invalid-json\n'
        self.flow_log.write_text(original_log, encoding="utf-8")
        self.server._LIVE_EVENT_CACHE["expires_at"] = 0
        # Boot-scoped views report the four malformed JSONL rows whose time
        # cannot be trusted. The unbounded audit view additionally reports the
        # five malformed database rows from the previous boot.
        self.assert_monitoring_available(expected_ignored=4, expected_unbounded_ignored=9)
        # A second read uses the cache and must keep the warning and valid task.
        self.assert_monitoring_available(expected_ignored=4, expected_unbounded_ignored=9)
        # Reload the same database through a new store, as after a restart.
        with patch.object(self.server, "EVENT_STORE", self.server.EventStore("sqlite:///" + str(self.database), "test-key")):
            self.server._LIVE_EVENT_CACHE["expires_at"] = 0
            self.assert_monitoring_available(expected_ignored=4, expected_unbounded_ignored=9)
        self.assertEqual(self.flow_log.read_text(encoding="utf-8"), original_log)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            preserved = [row[0] for row in connection.execute("SELECT payload FROM audit_events WHERE event_id LIKE 'legacy-%' ORDER BY event_id")]
        self.assertEqual(preserved, legacy_payloads)

    def test_legal_optional_containers_and_independent_approval_identifiers_survive(self):
        self.add_valid_task()
        event = {
            "event_type": "approval_event", "task_id": "valid-task", "adapter": "openclaw",
            "review_id": "AGR-ONE", "approval_id": "APP-ONE", "review_decision": "approve",
            "approval_scope": "once", "call_id": "CALL-ONE", "tool_call_id": "TOOL-ONE", "operation_id": "OP-ONE",
            "proposed_tool_call": {"name": "read", "params": {"options": ["text", {"limit": 1}]}},
            "parameters": None, "security_control": {"controls": None},
            "scoring_details": None, "triggered_rules": ["POL-001", {"rule_id": "POL-002"}],
            "findings": [{"message": "structured finding"}], "evidence": {"details": ["structured evidence"]},
        }
        status, response = self.request("/api/events", event, post=True)
        self.assertEqual(status, 201, response)
        status, payload = self.request("/api/live/events")
        self.assertEqual(status, 200)
        actual = next(item for item in payload["events"] if item["event_type"] == "approval_event")
        for key in ("review_id", "approval_id", "review_decision", "approval_scope", "call_id", "tool_call_id", "operation_id"):
            self.assertEqual(actual[key], event[key])
        self.assertEqual(actual["triggered_rules"], ["POL-001", "POL-002"])
        self.assert_monitoring_available()


if __name__ == "__main__":
    unittest.main()
