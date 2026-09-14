from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any

from .event_protocol import normalize_event


class EventStore:
    def __init__(self, database_url: str, signing_key: str):
        self.database_url = database_url
        self.signing_key = signing_key.encode("utf-8")
        self._lock = Lock()
        self._backend = "postgresql" if database_url.startswith(("postgresql://", "postgres://")) else "sqlite"
        self._initialize()

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = normalize_event(payload)
        canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._lock:
            connection = self._connect()
            try:
                self._begin_append(connection)
                previous = self._latest_signature(connection)
                signature = hmac.new(self.signing_key, f"{previous}|{canonical}".encode("utf-8"), hashlib.sha256).hexdigest()
                if not self._insert(connection, event, canonical, previous, signature):
                    previous, signature = self._event_signatures(connection, event["event_id"])
                connection.commit()
            finally:
                connection.close()
        return {**event, "previous_signature": previous, "audit_signature": signature}

    def list_events(
        self,
        limit: int | None = 10000,
        ascending: bool = True,
        *,
        since: str = "",
        until: str = "",
        diagnostics: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            order = "ASC" if ascending else "DESC"
            placeholder = "?" if self._backend == "sqlite" else "%s"
            clauses: list[str] = []
            parameters: list[Any] = []
            if since:
                clauses.append(f"timestamp >= {placeholder}")
                parameters.append(since)
            if until:
                clauses.append(f"timestamp < {placeholder}")
                parameters.append(until)
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            limit_clause = ""
            if limit is not None:
                parameters.append(max(1, limit))
                limit_clause = f" LIMIT {placeholder}"
            rows = connection.execute(
                f"SELECT payload, previous_signature, signature FROM audit_events{where} "
                f"ORDER BY sequence {order}{limit_clause}",
                tuple(parameters),
            ).fetchall()
            events = []
            for row in rows:
                try:
                    event = json.loads(row[0])
                    if not isinstance(event, dict):
                        raise TypeError("stored event is not an object")
                except (ValueError, TypeError, RecursionError, OverflowError):
                    if diagnostics is not None:
                        diagnostics["invalid_records"] = diagnostics.get("invalid_records", 0) + 1
                    continue
                events.append({**event, "previous_signature": row[1], "audit_signature": row[2]})
            return events
        finally:
            connection.close()

    def verify_chain(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT sequence, payload, previous_signature, signature FROM audit_events ORDER BY sequence ASC"
            ).fetchall() if self._backend == "sqlite" else self._pg_verify_rows(connection)
        finally:
            connection.close()
        previous = ""
        for sequence, canonical, stored_previous, signature in rows:
            expected = hmac.new(self.signing_key, f"{previous}|{canonical}".encode("utf-8"), hashlib.sha256).hexdigest()
            if stored_previous != previous or not hmac.compare_digest(signature, expected):
                return {"valid": False, "count": len(rows), "broken_sequence": sequence}
            previous = signature
        return {"valid": True, "count": len(rows), "head_signature": previous}

    def chain_head(self) -> dict[str, Any]:
        """Return constant-size liveness metadata without verifying the chain.

        Full verification intentionally remains in ``verify_chain``. Calling it
        from a one-second health probe makes startup time proportional to audit
        history size and can put the plugin into a kill/restart loop on a mature
        installation.
        """
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT sequence, signature FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
        if not row:
            return {
                "verification": "deferred",
                "latest_sequence": 0,
                "head_signature": "",
            }
        return {
            "verification": "deferred",
            "latest_sequence": int(row[0]),
            "head_signature": str(row[1]),
        }

    def _connect(self):
        if self._backend == "sqlite":
            path = Path(self.database_url.removeprefix("sqlite:///"))
            path.parent.mkdir(parents=True, exist_ok=True)
            return sqlite3.connect(path, timeout=10)
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("PostgreSQL storage requires psycopg[binary]") from exc
        return psycopg.connect(self.database_url)

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            sql = """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_signature TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
            """ if self._backend == "sqlite" else """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence BIGSERIAL PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_signature TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
            """
            connection.execute(sql)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp)")
            connection.commit()
        finally:
            connection.close()

    def _latest_signature(self, connection) -> str:
        row = connection.execute("SELECT signature FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
        return str(row[0]) if row else ""

    def _begin_append(self, connection) -> None:
        if self._backend == "sqlite":
            connection.execute("BEGIN IMMEDIATE")
        else:
            connection.execute("LOCK TABLE audit_events IN EXCLUSIVE MODE")

    def _insert(self, connection, event, canonical, previous, signature) -> bool:
        parameters = (event["event_id"], event["timestamp"], event["event_type"], canonical, previous, signature)
        if self._backend == "sqlite":
            cursor = connection.execute(
                "INSERT OR IGNORE INTO audit_events(event_id,timestamp,event_type,payload,previous_signature,signature) VALUES(?,?,?,?,?,?)",
                parameters,
            )
        else:
            cursor = connection.execute(
                "INSERT INTO audit_events(event_id,timestamp,event_type,payload,previous_signature,signature) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(event_id) DO NOTHING",
                parameters,
            )
        return cursor.rowcount > 0

    def _event_signatures(self, connection, event_id: str) -> tuple[str, str]:
        placeholder = "?" if self._backend == "sqlite" else "%s"
        row = connection.execute(
            f"SELECT previous_signature, signature FROM audit_events WHERE event_id = {placeholder}",
            (event_id,),
        ).fetchone()
        if not row:
            raise RuntimeError(f"event insert was ignored but no stored event exists: {event_id}")
        return str(row[0]), str(row[1])

    def _pg_fetch(self, connection, order: str, limit: int):
        return connection.execute(
            f"SELECT payload, previous_signature, signature FROM audit_events ORDER BY sequence {order} LIMIT %s",
            (max(1, limit),),
        ).fetchall()

    def _pg_verify_rows(self, connection):
        return connection.execute(
            "SELECT sequence, payload, previous_signature, signature FROM audit_events ORDER BY sequence ASC"
        ).fetchall()
