from __future__ import annotations

import json
import os
import tempfile
import threading
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="agentmeter-server-") as temp:
        os.environ["AGENTMETER_PORT"] = "0"
        os.environ["AGENTMETER_DATABASE_URL"] = f"sqlite:///{Path(temp) / 'events.db'}"
        os.environ["AGENTMETER_FLOW_LOG"] = str(Path(temp) / "flow-events.jsonl")
        os.environ["AGENTMETER_REQUIRE_AUTH"] = "true"
        os.environ["AGENTMETER_API_TOKEN"] = "integration-token"
        import server

        httpd = server.ThreadingHTTPServer((server.SETTINGS.host, 0), server.AgentMeterHandler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            # A liveness probe must not scan the complete audit chain. On a
            # large production database that exceeded the plugin's one-second
            # readiness timeout and caused a backend restart loop.
            original_verify_chain = server.EVENT_STORE.verify_chain
            server.EVENT_STORE.verify_chain = lambda: (_ for _ in ()).throw(
                AssertionError("/health must not perform full chain verification")
            )
            health = get_json(f"http://127.0.0.1:{port}/health")
            server.EVENT_STORE.verify_chain = original_verify_chain
            unauthorized = get_status(f"http://127.0.0.1:{port}/api/live/events")
            stored = post_json(f"http://127.0.0.1:{port}/api/events", {
                "schema_version": "agentmeter.event.v1",
                "adapter": "integration-test",
                "event_type": "output_guard_event",
                "timestamp": "2026-08-14T00:00:00Z",
                "surface": "message",
                "action": "redact",
            }, token="integration-token")
            stored_block = post_json(f"http://127.0.0.1:{port}/api/events", {
                "schema_version": "agentmeter.event.v1",
                "adapter": "integration-test",
                "event_type": "memory_governance_event",
                "timestamp": "2026-08-14T00:00:01Z",
                "surface": "memory_write",
                "action": "block_and_clean",
            }, token="integration-token")
            base_time = datetime(2026, 8, 14, 1, 0, tzinfo=timezone.utc)
            for index in range(83):
                server.EVENT_STORE.append({
                    "schema_version": "agentmeter.event.v1",
                    "adapter": "pagination-test",
                    "event_type": "risk_decision_event",
                    "timestamp": (base_time + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
                    "session_key": "pagination-over-80",
                    "tool_name": "read_document",
                    "gate_action": "allow",
                    "risk_score": 6,
                })
            verified = post_json(f"http://127.0.0.1:{port}/api/audit/verify", {}, token="integration-token")
            first_page = get_json(f"http://127.0.0.1:{port}/api/live/events?limit=1&offset=0", token="integration-token")
            second_page = get_json(f"http://127.0.0.1:{port}/api/live/events?limit=1&offset=1", token="integration-token")
            blocked_page = get_json(f"http://127.0.0.1:{port}/api/live/events?limit=10&offset=0&action=block", token="integration-token")
            latest_80 = get_json(f"http://127.0.0.1:{port}/api/live/events?limit=80&offset=0", token="integration-token")
            older_page = get_json(f"http://127.0.0.1:{port}/api/live/events?limit=80&offset=80", token="integration-token")
            live_summary = get_json(f"http://127.0.0.1:{port}/api/live/summary", token="integration-token")
            generic_gate = post_json(f"http://127.0.0.1:{port}/api/v1/evaluate", {
                "schema_version": "agentmeter.event.v1",
                "adapter": "generic-integration",
                "event_type": "tool_proposal",
                "timestamp": "2026-08-14T00:00:02Z",
                "task": {
                    "id": "generic-adapter-test",
                    "user_id": "integration-user",
                    "goal": "Read a public project document",
                },
                "context": {
                    "input_sources": [{"name": "user", "type": "user", "trust": "high"}],
                },
                "operation": {
                    "name": "read_document",
                    "parameters": {"path": "docs/public-readme.md"},
                    "data_classification": "public",
                },
            }, token="integration-token")
            task_item = server._build_task_item("task-peak-test", [
                {
                    "event_type": "input_event",
                    "timestamp": "2026-08-14T02:00:00Z",
                    "task_id": "task-peak-test",
                    "user_goal": "Update two internal task states and verify the result.",
                },
                {
                    "event_type": "risk_decision_event",
                    "timestamp": "2026-08-14T02:00:01Z",
                    "task_id": "task-peak-test",
                    "tool_name": "write_file",
                    "gate_action": "human_review",
                    "risk_score": 55,
                },
                {
                    "event_type": "risk_decision_event",
                    "timestamp": "2026-08-14T02:00:02Z",
                    "task_id": "task-peak-test",
                    "tool_name": "read_document",
                    "gate_action": "allow",
                    "risk_score": 10,
                },
            ])
            blocked_then_read = server._task_status([
                {"event_type": "risk_decision_event", "gate_action": "block"},
                {"event_type": "risk_decision_event", "gate_action": "allow"},
            ])
            assert health["status"] == "ok"
            assert health["audit_chain"]["verification"] == "deferred"
            assert unauthorized == 401
            assert stored["accepted"] is True
            assert stored_block["accepted"] is True
            assert verified["valid"] is True
            assert len(first_page["events"]) == 1
            assert first_page["total"] >= 2
            assert first_page["has_more"] is True
            assert first_page["events"][0]["event_id"] != second_page["events"][0]["event_id"]
            assert blocked_page["total"] >= 1
            assert all((item.get("gate_action") or item.get("action", "")).startswith("block") for item in blocked_page["events"])
            assert latest_80["total"] == 85
            assert len(latest_80["events"]) == 80
            assert len(older_page["events"]) == 5
            assert {item["event_id"] for item in latest_80["events"]}.isdisjoint(
                item["event_id"] for item in older_page["events"]
            )
            assert live_summary["window"]["event_count"] == 85
            assert generic_gate["schema_version"] == "agentmeter.event.v1"
            assert generic_gate["adapter"] == "generic-integration"
            assert task_item["max_risk_score"] == 55
            assert task_item["peak_risk_score"] == 55
            assert task_item["peak_action"] == "human_review"
            assert task_item["peak_decision"]["tool_name"] == "write_file"
            assert task_item["latest_decision"]["risk_score"] == 10
            assert task_item["latest_action"] == "allow"
            assert blocked_then_read == "blocked"
        finally:
            httpd.shutdown()
            httpd.server_close()
    print({"total": 25, "passed": 25})


def get_json(url: str, token: str = "") -> dict:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def post_json(url: str, payload: dict, token: str = "") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def get_status(url: str) -> int:
    try:
        urllib.request.urlopen(url, timeout=5)
    except urllib.error.HTTPError as error:
        return error.code
    return 200


if __name__ == "__main__":
    main()
