from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    environment: str
    api_token: str
    require_auth: bool
    database_url: str
    flow_log_paths: tuple[Path, ...]
    audit_signing_key: str
    max_log_bytes: int
    log_backups: int


def load_settings() -> Settings:
    environment = os.getenv("AGENTMETER_ENV", "development").strip().lower()
    api_token = os.getenv("AGENTMETER_API_TOKEN", "")
    audit_signing_key = os.getenv("AGENTMETER_AUDIT_SIGNING_KEY", "development-only-audit-key")
    require_auth = _bool("AGENTMETER_REQUIRE_AUTH", environment == "production")
    if require_auth and not api_token:
        raise RuntimeError("AGENTMETER_API_TOKEN is required when authentication is enabled")
    if environment == "production" and audit_signing_key == "development-only-audit-key":
        raise RuntimeError("AGENTMETER_AUDIT_SIGNING_KEY is required in production")
    raw_flow_logs = os.getenv("AGENTMETER_FLOW_LOGS") or os.getenv(
        "AGENTMETER_FLOW_LOG", str(ROOT / "data" / "openclaw_guard_flow_events.jsonl")
    )
    flow_log_paths = tuple(
        Path(item.strip()).expanduser().resolve()
        for item in raw_flow_logs.split(os.pathsep)
        if item.strip()
    )
    return Settings(
        host=os.getenv("AGENTMETER_HOST", "127.0.0.1"),
        port=int(os.getenv("AGENTMETER_PORT", "8765")),
        environment=environment,
        api_token=api_token,
        require_auth=require_auth,
        database_url=os.getenv("AGENTMETER_DATABASE_URL", f"sqlite:///{ROOT / 'data' / 'agentmeter.db'}"),
        flow_log_paths=flow_log_paths,
        audit_signing_key=audit_signing_key,
        max_log_bytes=int(os.getenv("AGENTMETER_MAX_LOG_BYTES", str(10 * 1024 * 1024))),
        log_backups=max(1, int(os.getenv("AGENTMETER_LOG_BACKUPS", "5"))),
    )
