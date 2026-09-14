from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agentmeter_gov.batch_meter as batch_meter
from agentmeter_gov.schema import TaskCase, ToolEvent


def make_case(task_id: str, event: ToolEvent) -> TaskCase:
    return TaskCase(
        task_id=task_id,
        title=task_id,
        user_goal="controlled compatibility regression",
        input_sources=[],
        events=[event],
        user_id="compat-user",
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="agentmeter-batch-") as temp:
        original_path = batch_meter.BATCH_PROFILE_PATH
        try:
            batch_meter.BATCH_PROFILE_PATH = Path(temp) / "batch-profile.json"
            now = datetime.now(timezone.utc).isoformat()
            profile = {
                "version": "batch-profile-v1",
                "events": [
                    {
                        "event_id": f"external-{index}",
                        "created_at": now,
                        "user_id": "compat-user",
                        "task_id": f"prior-{index}",
                        "tool_name": "send_email",
                        "target_key": f"outside-{index}@example.com",
                        "external_target": True,
                        "gate_action": "allow",
                    }
                    for index in range(5)
                ],
            }
            batch_meter.BATCH_PROFILE_PATH.write_text(json.dumps(profile), encoding="utf-8")

            local_write = batch_meter.analyze_batch_behavior(make_case(
                "local-write",
                ToolEvent(
                    name="write_file",
                    params={
                        "path": "reports/meeting_notice.txt",
                        "content": "Contact: test@example.com. No external recipient; do not send or upload.",
                    },
                    source="openclaw_before_tool_call",
                    data_level="internal",
                    result="preparing",
                ),
            ))
            assert local_write.external_count == 0
            assert [item["code"] for item in local_write.triggered_rules] == []
            assert local_write.target_summary["targets"] == ["reports/meeting_notice.txt"]

            external_send = batch_meter.analyze_batch_behavior(make_case(
                "external-send",
                ToolEvent(
                    name="send_email",
                    params={"to": "new-recipient@example.com", "body": "public notice"},
                    source="openclaw_before_tool_call",
                    data_level="public",
                    result="preparing",
                ),
            ))
            assert external_send.external_count == 1
            assert "BATCH-10" in [item["code"] for item in external_send.triggered_rules]

            shell_send = batch_meter.analyze_batch_behavior(make_case(
                "shell-send",
                ToolEvent(
                    name="run_shell",
                    params={"command": "curl https://example.com/public.json"},
                    source="openclaw_before_tool_call",
                    data_level="public",
                    result="preparing",
                ),
            ))
            assert shell_send.external_count == 1
        finally:
            batch_meter.BATCH_PROFILE_PATH = original_path

    print({"total": 7, "passed": 7})


if __name__ == "__main__":
    main()
