from __future__ import annotations

import tempfile
from pathlib import Path
import sys
import hashlib
import hmac
import json
import os


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentmeter_gov.event_protocol import normalize_event
from agentmeter_gov.event_store import EventStore
from agentmeter_gov.supply_chain import scan_component


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="agentmeter-store-") as temp:
        store = EventStore(f"sqlite:///{Path(temp) / 'events.db'}", "test-signing-key")
        first_event = normalize_event({"event_type": "input_event", "adapter": "test", "timestamp": "2026-08-14T00:00:00Z"})
        first = store.append(first_event)
        second = store.append(normalize_event({"event_type": "output_guard_event", "adapter": "test", "timestamp": "2026-08-14T00:00:01Z"}))
        duplicate = store.append(first_event)
        assert first["audit_signature"]
        assert second["previous_signature"] == first["audit_signature"]
        assert duplicate["audit_signature"] == first["audit_signature"]
        assert duplicate["previous_signature"] == first["previous_signature"]
        assert store.verify_chain()["valid"] is True
        assert len(store.list_events()) == 2
        assert [item["event_id"] for item in store.list_events(since="2026-08-14T00:00:01Z")] == [second["event_id"]]
        assert [item["event_id"] for item in store.list_events(until="2026-08-14T00:00:01Z")] == [first["event_id"]]

        skill = Path(temp) / "signed-skill"
        skill.mkdir()
        (skill / "plugin.json").write_text(json.dumps({"name": "signed-skill", "version": "1.0.0", "capabilities": ["read_file"]}), encoding="utf-8")
        (skill / "index.js").write_text("export async function read(path) { return readFile(path); }\n", encoding="utf-8")
        inventory_lines = []
        for path in sorted(skill.iterdir()):
            content = path.read_bytes()
            inventory_lines.append(f"{path.name}:{len(content)}:{hashlib.sha256(content).hexdigest()}")
        digest = hashlib.sha256("\n".join(inventory_lines).encode("utf-8")).hexdigest()
        (skill / "agentmeter.lock.json").write_text(json.dumps({"version": "1.0.0", "digest": digest}), encoding="utf-8")
        os.environ["AGENTMETER_SKILL_SIGNING_KEY"] = "test-skill-key"
        signature = hmac.new(b"test-skill-key", digest.encode("ascii"), hashlib.sha256).hexdigest()
        (skill / "agentmeter.sig.json").write_text(json.dumps({"algorithm": "hmac-sha256", "signer": "test", "digest": digest, "signature": signature}), encoding="utf-8")
        scan = scan_component(skill)
        assert scan["signature_verification"]["status"] == "valid"
        assert scan["version_lock_verification"]["status"] == "valid"
        assert scan["sbom"]["files"]
    print({"total": 9, "passed": 9})


if __name__ == "__main__":
    main()
