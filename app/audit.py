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

    Design choices:
    - Store a SHA-256 hash of the prompt instead of the raw prompt.
    - Store validation decisions, violations, status, timestamps, and attempts.
    - Persist records across server restarts.
    - Support human review status for high-risk governance workflow.
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

        self._ensure_review_columns()

    def _ensure_review_columns(self):
        """
        Adds review columns to existing local SQLite database if they do not exist.
        This keeps the project backwards-compatible with older audit_events.db files.
        """
        with self._connect() as conn:
            existing_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
            }

            if "review_status" not in existing_columns:
                conn.execute("ALTER TABLE audit_events ADD COLUMN review_status TEXT DEFAULT 'pending'")

            if "review_note" not in existing_columns:
                conn.execute("ALTER TABLE audit_events ADD COLUMN review_note TEXT DEFAULT ''")

            if "reviewed_at" not in existing_columns:
                conn.execute("ALTER TABLE audit_events ADD COLUMN reviewed_at TEXT DEFAULT ''")

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
            "review_status": "pending",
            "review_note": "",
            "reviewed_at": "",
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
                    attempts,
                    review_status,
                    review_note,
                    reviewed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event["review_status"],
                    event["review_note"],
                    event["reviewed_at"],
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
                    attempts,
                    COALESCE(review_status, 'pending'),
                    COALESCE(review_note, ''),
                    COALESCE(reviewed_at, '')
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
                    "review_status": row[8],
                    "review_note": row[9],
                    "reviewed_at": row[10],
                }
            )

        return [enrich_event_with_risk(event) for event in events]

    def update_review_status(
        self,
        event_id: str,
        review_status: str,
        review_note: str = "",
    ) -> Dict[str, Any]:
        allowed_statuses = {"pending", "reviewed", "needs_follow_up"}

        if review_status not in allowed_statuses:
            raise ValueError(
                "Invalid review_status. Use pending, reviewed, or needs_follow_up."
            )

        reviewed_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE audit_events
                SET review_status = ?,
                    review_note = ?,
                    reviewed_at = ?
                WHERE event_id = ?
                """,
                (review_status, review_note, reviewed_at, event_id),
            )
            conn.commit()

        events = [event for event in self.list_events() if event["event_id"] == event_id]

        if not events:
            raise ValueError("Event not found.")

        return events[0]

    def review_queue(self) -> List[Dict[str, Any]]:
        """
        Return events that should be reviewed.
        For this educational project, high/critical risks and fallback/blocked events are review candidates.
        """
        events = self.list_events()

        queue = []
        for event in events:
            if event.get("review_status") != "pending":
                continue

            if (
                event.get("risk_level") in {"high", "critical"}
                or event.get("status") in {"blocked", "fallback"}
            ):
                queue.append(event)

        return queue


audit_logger = AuditLogger()
