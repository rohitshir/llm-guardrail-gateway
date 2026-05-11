from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4
from .risk import enrich_event_with_risk


class AuditLogger:
    """
    Educational SQLite-backed audit logger.

    Design choice:
    - Store a SHA-256 hash of the prompt instead of the raw prompt.
    - Store validation decisions, violations, status, timestamps, and attempts.
    - Persist records across server restarts.
    """

    def __init__(self):
        root = Path(__file__).resolve().parent.parent
        data_dir = root / "data"
        data_dir.mkdir(exist_ok=True)

        self.db_path = data_dir / "audit_events.db"
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    model TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    violations_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def prompt_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def record(
        self,
        status: str,
        model: str,
        policy_id: str,
        user_text: str,
        violations: list,
        attempts: int,
    ) -> Dict[str, Any]:
        event = {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "model": model,
            "policy_id": policy_id,
            "prompt_hash": self.prompt_hash(user_text),
            "violations": [
                v.model_dump() if hasattr(v, "model_dump") else v
                for v in violations
            ],
            "attempts": attempts,
        }

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id,
                    timestamp,
                    status,
                    model,
                    policy_id,
                    prompt_hash,
                    violations_json,
                    attempts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"],
                    event["timestamp"],
                    event["status"],
                    event["model"],
                    event["policy_id"],
                    event["prompt_hash"],
                    json.dumps(event["violations"]),
                    event["attempts"],
                ),
            )
            conn.commit()

        return enrich_event_with_risk(event)

    def list_events(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    event_id,
                    timestamp,
                    status,
                    model,
                    policy_id,
                    prompt_hash,
                    violations_json,
                    attempts
                FROM audit_events
                ORDER BY timestamp DESC
                LIMIT 100
                """
            ).fetchall()

        events = []
        for row in rows:
            events.append(
                {
                    "event_id": row[0],
                    "timestamp": row[1],
                    "status": row[2],
                    "model": row[3],
                    "policy_id": row[4],
                    "prompt_hash": row[5],
                    "violations": json.loads(row[6]),
                    "attempts": row[7],
                }
            )

        return [enrich_event_with_risk(event) for event in events]


audit_logger = AuditLogger()
