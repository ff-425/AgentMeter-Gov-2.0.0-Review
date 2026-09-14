"""Read-only HTTP benchmark against an isolated synthetic audit log, never live data."""
import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


def main():
    with tempfile.TemporaryDirectory(prefix="agentmeter-perf-") as folder:
        root = Path(folder)
        flow = root / "flow.jsonl"
        os.environ.update(AGENTMETER_DATABASE_URL="sqlite:///" + str(root / "audit.db"),
                          AGENTMETER_FLOW_LOG=str(flow), AGENTMETER_FLOW_LOGS=str(flow),
                          AGENTMETER_REQUIRE_AUTH="false")
        with flow.open("w", encoding="utf-8") as stream:
            for index in range(6000):
                common = {"task_id": f"fixture-{index}", "timestamp": "2026-09-01T00:00:00Z", "adapter": "benchmark"}
                for kind, extra in (
                    ("input_event", {"user_goal": f"Synthetic task {index}: " + "normal internal summary " * 40}),
                    ("risk_decision_event", {"tool_name": "read_file", "risk_score": 12, "gate_action": "allow",
                                             "parameters": {"path": f"fixture/{index}.txt", "context": "fixture " * 100}}),
                    ("result_event", {"status": "success"}),
                ):
                    stream.write(json.dumps({**common, **extra, "event_type": kind, "event_id": f"{index}-{kind}"}) + "\n")
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import server
        httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.AgentMeterHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f"http://127.0.0.1:{httpd.server_address[1]}/api/live/tasks?scope=history"
        if "--compact" in sys.argv:
            url += "&format=compact"
        results = {"fixture_tasks": 6000, "fixture_events": 18000}
        etag = ""
        try:
            for name in ("cold", "warm", "unchanged", "append"):
                if name == "append":
                    server.EVENT_STORE.append({"event_type": "input_event", "task_id": "new-fixture",
                        "user_goal": "Additional fixture", "timestamp": "2026-09-02T00:00:00Z"})
                headers = {"Accept-Encoding": "gzip"}
                if name in {"unchanged", "append"}:
                    headers["If-None-Match"] = etag
                start = time.perf_counter()
                try:
                    response = opener.open(urllib.request.Request(url, headers=headers))
                except urllib.error.HTTPError as error:
                    if error.code != 304:
                        raise
                    response = error
                with response:
                    body = response.read()
                    results[name] = {"elapsed_ms": round((time.perf_counter() - start) * 1000, 2),
                                     "status": response.code, "wire_bytes": len(body)}
                    if body:
                        decoded = gzip.decompress(body)
                        payload = json.loads(decoded)
                        assert len(payload["tasks"]) == (6001 if name == "append" else 6000)
                        assert sum(len(task["events"]) for task in payload["tasks"]) == (18001 if name == "append" else 18000)
                        results[name]["json_bytes"] = len(decoded)
                        etag = response.headers["ETag"]
            print(json.dumps(results, indent=2))
            if len(sys.argv) > 1:
                Path(sys.argv[1]).write_text(json.dumps(results, indent=2), encoding="utf-8")
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    main()
