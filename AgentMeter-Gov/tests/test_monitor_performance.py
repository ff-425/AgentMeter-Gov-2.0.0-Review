"""Monitoring read-cache and lossless transport regressions; isolated evidence only."""
from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class MonitorPerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="agentmeter-monitor-speed-")
        cls.path = Path(cls.directory.name)
        os.environ.update(AGENTMETER_DATABASE_URL="sqlite:///" + str(cls.path / "audit.db"),
                          AGENTMETER_FLOW_LOG=str(cls.path / "flow.jsonl"), AGENTMETER_REQUIRE_AUTH="false")
        import server
        cls.server = server
        cls.overrides = [patch.object(server, "SETTINGS", server.load_settings()),
                         patch.object(server, "FLOW_LOGS", (cls.path / "flow.jsonl",)),
                         patch.object(server, "EVENT_STORE", server.EventStore("sqlite:///" + str(cls.path / "audit.db"), "fixture-key"))]
        for override in cls.overrides:
            override.start()
        server._LIVE_EVENT_CACHE["expires_at"] = 0
        server._TASK_RESPONSE_CACHE.clear()
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.AgentMeterHandler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:" + str(cls.httpd.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for override in reversed(cls.overrides):
            override.stop()
        cls.directory.cleanup()

    def add(self, name):
        return self.server.EVENT_STORE.append({"event_type": "input_event", "task_id": name,
            "timestamp": "2026-08-15T00:00:00Z", "adapter": "isolated-speed-test",
            "user_goal": "Synthetic regression fixture " + name})

    def test_revision_cache_survives_timer_and_scope_switch(self):
        self.add("cached-history")
        self.server._LIVE_EVENT_CACHE["expires_at"] = 0
        with patch.object(self.server.EVENT_STORE, "list_events", wraps=self.server.EVENT_STORE.list_events) as read:
            history = self.server.load_live_events()
            self.server.load_live_events(since="2026-09-12T00:00:00Z")
            with patch.object(self.server.time, "monotonic", return_value=10**12):
                self.assertIs(self.server.load_live_events(), history)
            self.assertEqual(read.call_count, 2)
            self.add("new-evidence")
            updated = self.server.load_live_events()
            self.assertEqual(read.call_count, 3)
            self.assertTrue(any(item["task_id"] == "new-evidence" for item in updated))

    def test_unchanged_request_skips_task_rebuild_and_database_append_reuses_logs(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = self.base + "/api/live/tasks?scope=history&format=compact"
        (self.path / "flow.jsonl").write_text(json.dumps({"event_type": "input_event", "event_id": "flow-cache-event",
            "task_id": "flow-cache-task", "timestamp": "2026-08-16T00:00:00Z", "user_goal": "Cached source fixture"}), encoding="utf-8")
        self.add("cache-transport")
        with opener.open(url) as response:
            etag = response.headers["ETag"]
        with patch.object(self.server, "build_task_history", side_effect=AssertionError("Unexpected full rebuild")):
            with self.assertRaises(urllib.error.HTTPError) as unchanged:
                opener.open(urllib.request.Request(url, headers={"If-None-Match": etag}))
            self.assertEqual(unchanged.exception.code, 304)
        self.server.load_live_events()
        self.add("append-reuses-flow")
        with patch.object(self.server, "slim_event", wraps=self.server.slim_event) as slim:
            self.server.load_live_events()
            self.assertFalse(any(call.args[0].get("event_id") == "flow-cache-event" for call in slim.call_args_list))

    def test_compact_payload_round_trips_all_event_fields_and_decisions(self):
        self.server.EVENT_STORE.append({"event_type": "risk_decision_event", "task_id": "compact-fixture",
            "timestamp": "2026-08-17T00:00:00Z", "user_goal": "Synthetic compact fixture",
            "gate_action": "block", "risk_score": 90, "parameters": {"token": "not-visible"},
            "gate_timings_ms": {"risk_semantic": 1.25}})
        self.server.EVENT_STORE.append({"event_type": "input_event", "task_id": "compact-fixture",
            "timestamp": "2026-08-16T00:00:00Z", "user_goal": "Synthetic compact fixture"})
        full = self.server.build_task_history(task_limit=None)
        compact = self.server.compact_task_payload(full)
        self.assertLess(len(json.dumps(compact)), len(json.dumps(full)))
        restored = {key: value for key, value in compact.items() if key not in {"transport", "event_defaults", "decision_refs"}}
        restored["tasks"] = []
        for task, refs in zip(compact["tasks"], compact["decision_refs"]):
            events = [{**compact["event_defaults"], **event} for event in task["events"]]
            restored["tasks"].append({**task, "events": events,
                "latest_decision": events[refs[0]] if refs[0] is not None else None,
                "peak_decision": events[refs[1]] if refs[1] is not None else None})
        self.assertEqual(restored, full)
        self.assertNotIn("not-visible", json.dumps(compact))

    def test_unicode_separators_inside_json_strings_are_not_corrupt_lines(self):
        event = {"event_type": "input_event", "event_id": "unicode-fixture", "task_id": "unicode-fixture",
                 "timestamp": "2026-08-16T00:00:00Z", "user_goal": "One\u2028Two\u2029Three"}
        (self.path / "flow.jsonl").write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")
        result = next(item for item in self.server.load_live_events() if item["event_id"] == event["event_id"])
        self.assertEqual(result["user_goal"], event["user_goal"])

    def test_audit_append_does_not_wait_on_monitor_read_lock(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        event = {"event_type": "input_event", "task_id": "nonblocking-audit", "user_goal": "Synthetic fixture"}
        with self.server._LIVE_EVENT_CACHE_LOCK:
            with opener.open(urllib.request.Request(self.base + "/api/events", data=json.dumps(event).encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=2) as response:
                self.assertEqual(response.status, 201)

    def test_jsonl_changes_invalidate_cache_without_timer(self):
        self.server.load_live_events()
        event = {"event_type": "input_event", "timestamp": "2026-08-16T00:00:00Z",
                 "event_id": "jsonl-speed-fixture", "task_id": "jsonl-only", "user_goal": "JSONL test fixture"}
        (self.path / "flow.jsonl").write_text(json.dumps(event), encoding="utf-8")
        self.assertTrue(any(item["event_id"] == event["event_id"] for item in self.server.load_live_events()))

    def test_redaction_shared_parameters_is_lossless_and_secret_safe(self):
        params = {"token": "never-display", "email": "test@example.org", "mobile": "13800138000", "ordinary": "preserve"}
        result = self.server.redact_for_dashboard({"parameters": params, "proposed_tool_call": {"params": params}})
        self.assertEqual(result["parameters"], result["proposed_tool_call"]["params"])
        self.assertEqual(result["parameters"]["ordinary"], "preserve")
        self.assertNotIn("never-display", json.dumps(result))
        self.assertNotIn("13800138000", json.dumps(result))
        self.assertEqual(params["token"], "never-display")

    def test_gzip_preserves_all_fields_and_honors_client_negotiation(self):
        self.server.EVENT_STORE.append({"event_type": "input_event", "task_id": "large-fixture",
            "timestamp": "2026-08-17T00:00:00Z", "adapter": "isolated-speed-test", "user_goal": "fixture " * 10000})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for encoding, compressed in (("gzip", True), ("gzip;q=0", False), ("identity", False)):
            request = urllib.request.Request(self.base + "/api/live/tasks?scope=history", headers={"Accept-Encoding": encoding})
            with opener.open(request) as response:
                body = response.read()
                self.assertEqual(int(response.headers["Content-Length"]), len(body))
                self.assertEqual(response.headers.get("Content-Encoding") == "gzip", compressed)
                if compressed:
                    decoded = gzip.decompress(body)
                    self.assertLess(len(body), len(decoded) / 4)
                else:
                    decoded = body
                payload = json.loads(decoded)
                self.assertEqual(payload["returned_task_count"], payload["task_count"])
                large = next(task for task in payload["tasks"] if task["task_id"] == "large-fixture")
                self.assertEqual(len(large["goal"]), 80000)
                self.assertEqual(large["events"][0]["user_goal"], large["goal"])

    def test_conditional_reads_detect_new_evidence_and_status_aging(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        at = datetime.now(timezone.utc) - timedelta(seconds=170)
        self.server.EVENT_STORE.append({"event_type": "input_event", "task_id": "aging-fixture",
            "timestamp": at.isoformat(), "adapter": "isolated-speed-test", "user_goal": "Synthetic aging fixture"})
        url = self.base + "/api/live/tasks?scope=history"
        with opener.open(url) as response:
            etag = response.headers["ETag"]
        request = urllib.request.Request(url, headers={"If-None-Match": etag})
        with self.assertRaises(urllib.error.HTTPError) as unchanged:
            opener.open(request)
        self.assertEqual(unchanged.exception.code, 304)
        future = datetime.now(timezone.utc) + timedelta(seconds=20)
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return future
        with patch.object(self.server, "datetime", Clock):
            with opener.open(request) as response:
                self.assertNotEqual(response.headers["ETag"], etag)
                task = next(item for item in json.load(response)["tasks"] if item["task_id"] == "aging-fixture")
                self.assertEqual(task["status"], "incomplete")
        self.add("conditional-new-fixture")
        with opener.open(request) as response:
            self.assertNotEqual(response.headers["ETag"], etag)
        with patch.object(self.server, "SETTINGS", replace(self.server.SETTINGS, require_auth=True, api_token="fixture-only")):
            with self.assertRaises(urllib.error.HTTPError) as denied:
                opener.open(request)
            self.assertEqual(denied.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
