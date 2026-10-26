
import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


class EventDatabase:
    """Store RDRS events and track incident investigations."""

    INCIDENT_STATUSES = {
        "Open",
        "Investigating",
        "Resolved",
        "False Positive",
    }

    def __init__(self, database_path: str = "data/rdrs.db"):
        self.path = Path(database_path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    path TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entropy REAL,
                    risk_score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reasons TEXT NOT NULL
                )
            """)

            # Store incident workflow separately from detection events.
            connection.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'Open',
                    notes TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES events(id)
                )
            """)

    def add_event(self, event: dict[str, Any]) -> int:
        with self.lock, self._connect() as connection:
            cursor = connection.execute("""
                INSERT INTO events (
                    path, action, entropy, risk_score,
                    severity, status, reasons
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event["path"],
                event["action"],
                event.get("entropy"),
                event["risk_score"],
                event["severity"],
                event["status"],
                json.dumps(event.get("reasons", [])),
            ))

            event_id = int(cursor.lastrowid)

            # Automatically create an incident for qualifying events.
            if event["risk_score"] >= 20:
                connection.execute("""
                    INSERT OR IGNORE INTO incidents (event_id)
                    VALUES (?)
                """, (event_id,))

            return event_id

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 1000))

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            item["reasons"] = json.loads(item["reasons"])
            results.append(item)

        return results

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 1000))

        with self._connect() as connection:
            rows = connection.execute("""
                SELECT
                    i.id AS incident_id,
                    i.status AS incident_status,
                    i.notes,
                    i.updated_at,
                    e.id AS event_id,
                    e.timestamp,
                    e.path,
                    e.action,
                    e.risk_score,
                    e.severity,
                    e.reasons
                FROM incidents i
                JOIN events e ON e.id = i.event_id
                ORDER BY i.id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            item["reasons"] = json.loads(item["reasons"])
            results.append(item)

        return results

    def update_incident(
        self,
        incident_id: int,
        status: str,
        notes: str = "",
    ) -> dict[str, Any] | None:
        if status not in self.INCIDENT_STATUSES:
            raise ValueError(
                f"Invalid status. Choose one of: "
                f"{', '.join(sorted(self.INCIDENT_STATUSES))}"
            )

        with self.lock, self._connect() as connection:
            cursor = connection.execute("""
                UPDATE incidents
                SET status = ?,
                    notes = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, notes, incident_id))

            if cursor.rowcount == 0:
                return None

            row = connection.execute("""
                SELECT * FROM incidents WHERE id = ?
            """, (incident_id,)).fetchone()

            return dict(row)
