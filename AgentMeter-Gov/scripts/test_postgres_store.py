from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentmeter_gov.event_protocol import normalize_event
from agentmeter_gov.event_store import EventStore


def main() -> None:
    database_url = os.getenv("AGENTMETER_TEST_POSTGRES_URL", "")
    if not database_url:
        print({"skipped": True, "reason": "AGENTMETER_TEST_POSTGRES_URL is not set"})
        return
    import psycopg

    with psycopg.connect(database_url) as connection:
        connection.execute("DROP TABLE IF EXISTS audit_events")
        connection.commit()

    store = EventStore(database_url, "postgres-integration-signing-key")
    first_event = normalize_event({
        "adapter": "postgres-integration",
        "event_type": "input_event",
        "timestamp": "2026-08-14T00:00:00Z",
    })
    first = store.append(first_event)
    second = store.append(normalize_event({
        "adapter": "postgres-integration",
        "event_type": "output_guard_event",
        "timestamp": "2026-08-14T00:00:01Z",
    }))
    duplicate = store.append(first_event)
    assert first["audit_signature"]
    assert second["previous_signature"] == first["audit_signature"]
    assert duplicate["audit_signature"] == first["audit_signature"]
    assert len(store.list_events()) == 2
    assert store.verify_chain()["valid"] is True

    with psycopg.connect(database_url) as connection:
        connection.execute("UPDATE audit_events SET payload = '{}' WHERE sequence = 2")
        connection.commit()
    assert store.verify_chain()["valid"] is False
    print({"total": 6, "passed": 6})


if __name__ == "__main__":
    main()
