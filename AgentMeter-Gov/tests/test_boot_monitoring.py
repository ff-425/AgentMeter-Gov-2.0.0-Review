from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    with tempfile.TemporaryDirectory(prefix="agentmeter-boot-test-") as directory:
        os.environ.update(AGENTMETER_DATABASE_URL="sqlite:///" + str(Path(directory)/"events.db"), AGENTMETER_FLOW_LOG=str(Path(directory)/"empty.jsonl"), AGENTMETER_REQUIRE_AUTH="false")
        import server
        boot = datetime.now(timezone.utc) - timedelta(minutes=10)
        recent = datetime.now(timezone.utc) - timedelta(seconds=10)
        def add(task_id, at, action=None, completed=False):
            common={"adapter":"boot-test-fixture","task_id":task_id,"timestamp":at.isoformat(),"session_key":task_id}
            server.EVENT_STORE.append({**common,"event_type":"input_event","user_goal":"Boot-scoped monitoring test"})
            if action:
                server.EVENT_STORE.append({**common,"event_type":"risk_decision_event","gate_action":action,"tool_name":"read","risk_score":80})
            if completed:
                server.EVENT_STORE.append({**common,"event_type":"result_event","status":"completed"})
            server._LIVE_EVENT_CACHE["expires_at"]=0
        for index in range(205):
            add("old-"+str(index),boot-timedelta(days=1),"human_review")
        # The offset representation must not trick a lexical timestamp comparison.
        add("old-offset",(boot-timedelta(seconds=1)).astimezone(timezone(timedelta(hours=8))),"block")
        httpd=server.ThreadingHTTPServer(("127.0.0.1",0),server.AgentMeterHandler)
        thread=threading.Thread(target=httpd.serve_forever,daemon=True);thread.start()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def get(path):
            with opener.open("http://127.0.0.1:"+str(httpd.server_address[1])+path,timeout=10) as response:return json.load(response)
        checks=[]
        try:
            with patch.object(server,"monitoring_boot_started_at",return_value=boot) as clock:
                result=get("/api/live/tasks?scope=current")
                assert result["tasks"]==[] and result["task_count"]==0
                assert result["monitoring_window_kind"]=="boot"
                assert get("/api/live/summary?scope=current")["window"]["event_count"]==0
                assert get("/api/health?scope=current")["audit"]["event_count"]==0
                historical=get("/api/live/tasks?scope=history")
                assert historical["task_count"]==206 and len(historical["tasks"])==206
                assert historical["monitoring_window_kind"]=="unbounded_audit"
                assert historical["monitoring_started_at"] is None
                assert get("/api/live/summary?scope=history")["window"]["event_count"]==412
                assert get("/api/health?scope=history")["audit"]["event_count"]==412
                checks.append("Current boot excludes old records; history retains all 206 previous-boot tasks")
                add("new-running",recent)
                add("new-pending",recent,"human_review")
                add("new-finished",recent,completed=True)
                current=get("/api/live/tasks?scope=current")
                assert current["task_count"]==3
                assert {task["status"] for task in current["tasks"]}=={"running","awaiting_review","completed"}
                assert get("/api/live/tasks?scope=current&active=true")["task_count"]==1
                assert get("/api/live/tasks?scope=history")["task_count"]==209
                assert get("/api/live/tasks?scope=history&since=1900-01-01T00%3A00%3A00Z")["task_count"]==209
                assert get("/api/live/tasks?scope=history&until="+boot.isoformat().replace("+", "%2B"))["task_count"]==206
                assert get("/api/live/tasks?scope=history&since="+boot.isoformat().replace("+", "%2B"))["task_count"]==3
                checks.append("New tasks recorded; current-running count excludes pending and completed tasks")
                server.SERVER_STARTED_AT=datetime.now(timezone.utc)
                assert get("/api/live/tasks?scope=history")["task_count"]==209
                assert get("/api/live/tasks?scope=current")["monitoring_started_at"]==boot.isoformat()
                checks.append("Service restart preserves history; explicit history date filters remain effective")
                for index in range(205):add("new-many-"+str(index),recent)
                for scope,expected in (("current",208),("history",414)):
                    result=get("/api/live/tasks?scope="+scope)
                    assert result["task_count"]==expected and len(result["tasks"])==expected
                assert len(server.EVENT_STORE.list_events(limit=None))==622
                checks.append("Current and history queries are not silently capped at 200 tasks")
                next_boot=datetime.now(timezone.utc)+timedelta(seconds=1)
                clock.return_value=next_boot
                assert get("/api/live/tasks?scope=current")["task_count"]==0
                assert get("/api/live/summary?scope=current")["window"]["high_risk_count"]==0
                assert get("/api/health?scope=current")["audit"]["event_count"]==0
                assert get("/api/live/tasks?scope=history")["task_count"]==414
                checks.append("Next boot resets the current view without deleting cross-boot history")
                clock.side_effect=RuntimeError("unavailable")
                result=get("/api/live/tasks?scope=current")
                assert result["tasks"]==[] and result["monitoring_error"]
                historical=get("/api/live/tasks?scope=history")
                assert historical["task_count"]==414 and not historical["monitoring_error"]
                checks.append("Boot-detection failure closes the current view but does not prevent explicit history access")
        finally:httpd.shutdown();httpd.server_close()
        print(json.dumps({"passed":len(checks),"checks":checks},ensure_ascii=False,indent=2))

if __name__=="__main__":main()
