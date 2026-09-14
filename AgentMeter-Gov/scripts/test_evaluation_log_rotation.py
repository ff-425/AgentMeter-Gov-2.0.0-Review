from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_group1_full_openclaw_live import read_rotated_jsonl


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="agentmeter-rotation-") as temp:
        current = Path(temp) / "events.jsonl"
        rotated = Path(f"{current}.1")
        rotated.write_text("\n".join([
            json.dumps({"event_id": "old-1", "value": 1}),
            json.dumps({"event_id": "shared", "value": "old"}),
        ]) + "\n", encoding="utf-8")
        current.write_text("\n".join([
            json.dumps({"event_id": "shared", "value": "old"}),
            json.dumps({"event_id": "new-1", "value": 2}),
        ]) + "\n", encoding="utf-8")
        events = read_rotated_jsonl(current)
        assert [item["event_id"] for item in events] == ["old-1", "shared", "new-1"]
        assert len(events) == 3
        assert events[-1]["value"] == 2
    print({"total": 3, "passed": 3})


if __name__ == "__main__":
    main()
