from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolEvent:
    name: str
    params: dict[str, Any]
    source: str
    data_level: str = "public"
    result: str = "success"
    evidence: str = ""


@dataclass
class TaskCase:
    task_id: str
    title: str
    user_goal: str
    input_sources: list[dict[str, Any]]
    events: list[ToolEvent]
    expected_label: str = "unknown"
    user_id: str = "anonymous"


@dataclass
class RiskFactor:
    code: str
    name: str
    score: int
    evidence: list[str] = field(default_factory=list)


@dataclass
class RiskDecision:
    task_id: str
    total_score: int
    incident_probability: float
    risk_interval: tuple[float, float]
    level: str
    action: str
    summary: str
    matched_rules: list[str]
    hard_blocks: list[str]
    factors: list[RiskFactor]
    risk_path: list[str]
    blocked_events: list[str]
    safe_outputs: list[str]
    control_plan: dict[str, Any] = field(default_factory=dict)
    scoring_details: dict[str, Any] = field(default_factory=dict)
