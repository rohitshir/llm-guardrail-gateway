from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4


class PolicyChangeLogger:
    """
    Educational SQLite-backed policy change logger.

    Purpose:
    - Track changes made through the safe policy editor.
    - Store old and new values for selected policy fields.
    - Store backup file path created before policy update.
    """

    def __init__(self):
        root = Path(__file__).resolve().parent.parent
        data_dir = root / "data"
        data_dir.mkdir(exist_ok=True)

        self.db_path = data_dir / "policy_changes.db"
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_changes (
                    change_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    changed_by TEXT NOT NULL,
                    changed_fields_json TEXT NOT NULL,
                    old_values_json TEXT NOT NULL,
                    new_values_json TEXT NOT NULL,
                    backup_path TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def selected_policy_values(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "blocked_topics": policy_data.get("business_rules", {}).get("blocked_topics", []),
            "blocked_competitors": policy_data.get("business_rules", {}).get("blocked_competitors", []),
            "require_citations": policy_data.get("output_guardrails", {}).get("require_citations", True),
            "retry_enabled": policy_data.get("retry", {}).get("enabled", True),
            "max_attempts": policy_data.get("retry", {}).get("max_attempts", 1),
        }

    def calculate_changed_fields(
        self,
        old_values: Dict[str, Any],
        new_values: Dict[str, Any],
    ) -> List[str]:
        changed = []

        for key in sorted(set(old_values.keys()) | set(new_values.keys())):
            if old_values.get(key) != new_values.get(key):
                changed.append(key)

        return changed

    def record_change(
        self,
        old_policy: Dict[str, Any],
        new_policy: Dict[str, Any],
        backup_path: str,
        changed_by: str = "local_admin",
    ) -> Dict[str, Any]:
        old_values = self.selected_policy_values(old_policy)
        new_values = self.selected_policy_values(new_policy)
        changed_fields = self.calculate_changed_fields(old_values, new_values)

        change = {
            "change_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "changed_by": changed_by,
            "changed_fields": changed_fields,
            "old_values": old_values,
            "new_values": new_values,
            "backup_path": backup_path,
        }

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO policy_changes (
                    change_id,
                    timestamp,
                    changed_by,
                    changed_fields_json,
                    old_values_json,
                    new_values_json,
                    backup_path
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    change["change_id"],
                    change["timestamp"],
                    change["changed_by"],
                    json.dumps(change["changed_fields"]),
                    json.dumps(change["old_values"]),
                    json.dumps(change["new_values"]),
                    change["backup_path"],
                ),
            )
            conn.commit()

        return change

    def list_changes(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    change_id,
                    timestamp,
                    changed_by,
                    changed_fields_json,
                    old_values_json,
                    new_values_json,
                    backup_path
                FROM policy_changes
                ORDER BY timestamp DESC
                LIMIT 100
                """
            ).fetchall()

        changes = []

        for row in rows:
            changes.append(
                {
                    "change_id": row[0],
                    "timestamp": row[1],
                    "changed_by": row[2],
                    "changed_fields": json.loads(row[3]),
                    "old_values": json.loads(row[4]),
                    "new_values": json.loads(row[5]),
                    "backup_path": row[6],
                }
            )

        return changes


policy_change_logger = PolicyChangeLogger()
