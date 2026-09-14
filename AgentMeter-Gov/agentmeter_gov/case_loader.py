from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import TaskCase, ToolEvent


def load_cases(path: str | Path) -> list[TaskCase]:
    raw_cases = json.loads(Path(path).read_text(encoding="utf-8"))
    return [parse_case(item) for item in raw_cases]


def load_case_files(paths: list[str | Path]) -> list[TaskCase]:
    cases: list[TaskCase] = []
    for path in paths:
        file_path = Path(path)
        if file_path.exists():
            cases.extend(load_cases(file_path))
    return cases


def parse_case(item: dict[str, Any]) -> TaskCase:
    return TaskCase(
        task_id=item["task_id"],
        title=item["title"],
        user_goal=item["user_goal"],
        input_sources=item.get("input_sources", []),
        events=[ToolEvent(**event) for event in item.get("events", [])],
        expected_label=item.get("expected_label", "unknown"),
    )


def case_to_dict(case: TaskCase) -> dict[str, Any]:
    return {
        "task_id": case.task_id,
        "title": case.title,
        "user_goal": case.user_goal,
        "expected_label": case.expected_label,
        "input_sources": case.input_sources,
        "events": [event.__dict__ for event in case.events],
    }
