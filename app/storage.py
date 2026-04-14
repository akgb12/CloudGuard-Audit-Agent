from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import sqlite3
import threading
from typing import Dict, List, Optional, Protocol

from app.models import Incident, SecurityEvent


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


class Store(Protocol):
    def save_event(self, event: SecurityEvent) -> None:
        ...

    def get_recent_events(
        self,
        since: datetime,
        actor: Optional[str] = None,
        source_ip: Optional[str] = None,
        resource: Optional[str] = None,
        limit: int = 500,
    ) -> List[SecurityEvent]:
        ...

    def list_events(self, limit: int = 1000) -> List[SecurityEvent]:
        ...

    def save_incident(self, incident: Incident) -> None:
        ...

    def list_incidents(self, limit: int = 500) -> List[Incident]:
        ...

    def clear_all(self) -> None:
        ...


class MemoryStore:
    def __init__(self) -> None:
        self._events: List[SecurityEvent] = []
        self._incidents: List[Incident] = []
        self._lock = threading.Lock()

    def save_event(self, event: SecurityEvent) -> None:
        with self._lock:
            self._events.append(event)

    def get_recent_events(
        self,
        since: datetime,
        actor: Optional[str] = None,
        source_ip: Optional[str] = None,
        resource: Optional[str] = None,
        limit: int = 500,
    ) -> List[SecurityEvent]:
        with self._lock:
            filtered = []
            for item in self._events:
                if item.event_time < since:
                    continue
                if actor and item.actor != actor:
                    continue
                if source_ip and item.source_ip != source_ip:
                    continue
                if resource and item.resource != resource:
                    continue
                filtered.append(item)
            filtered.sort(key=lambda item: item.event_time, reverse=True)
            return filtered[: max(1, min(limit, 5000))]

    def list_events(self, limit: int = 1000) -> List[SecurityEvent]:
        with self._lock:
            sorted_events = sorted(self._events, key=lambda item: item.ingest_time or item.event_time, reverse=True)
            return sorted_events[: max(1, min(limit, 5000))]

    def save_incident(self, incident: Incident) -> None:
        with self._lock:
            self._incidents.append(incident)

    def list_incidents(self, limit: int = 500) -> List[Incident]:
        with self._lock:
            sorted_incidents = sorted(
                self._incidents,
                key=lambda item: item.detection_time or item.created_at,
                reverse=True,
            )
            return sorted_incidents[: max(1, min(limit, 5000))]

    def clear_all(self) -> None:
        with self._lock:
            self._events.clear()
            self._incidents.clear()


class SQLiteStore:
    def __init__(self, sqlite_path: str) -> None:
        db_dir = os.path.dirname(sqlite_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._connection = sqlite3.connect(sqlite_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    event_time TEXT NOT NULL,
                    ingest_time TEXT,
                    source TEXT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT,
                    source_ip TEXT,
                    auth_success INTEGER,
                    bytes_out INTEGER,
                    scenario_id TEXT,
                    is_attack INTEGER,
                    metadata_json TEXT
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    incident_type TEXT NOT NULL,
                    risk_score REAL,
                    confidence REAL,
                    status TEXT,
                    created_at TEXT,
                    detection_time TEXT,
                    triage_time TEXT,
                    recommendation_time TEXT,
                    scenario_id TEXT,
                    related_event_ids_json TEXT,
                    summary TEXT,
                    recommendation TEXT,
                    labels_json TEXT
                )
                """
            )

    def save_event(self, event: SecurityEvent) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id, event_time, ingest_time, source, actor, action, resource,
                    source_ip, auth_success, bytes_out, scenario_id, is_attack, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_time.isoformat(),
                    event.ingest_time.isoformat() if event.ingest_time else None,
                    event.source,
                    event.actor,
                    event.action,
                    event.resource,
                    event.source_ip,
                    int(event.auth_success) if event.auth_success is not None else None,
                    event.bytes_out,
                    event.scenario_id,
                    int(event.is_attack),
                    json.dumps(event.metadata, sort_keys=True),
                ),
            )

    def get_recent_events(
        self,
        since: datetime,
        actor: Optional[str] = None,
        source_ip: Optional[str] = None,
        resource: Optional[str] = None,
        limit: int = 500,
    ) -> List[SecurityEvent]:
        query = (
            "SELECT * FROM events WHERE event_time >= ?"
        )
        params: List[object] = [since.isoformat()]

        if actor:
            query += " AND actor = ?"
            params.append(actor)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if resource:
            query += " AND resource = ?"
            params.append(resource)

        query += " ORDER BY event_time DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))

        with self._lock:
            rows = self._connection.execute(query, tuple(params)).fetchall()

        return [self._event_from_row(row) for row in rows]

    def list_events(self, limit: int = 1000) -> List[SecurityEvent]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM events ORDER BY ingest_time DESC LIMIT ?",
                (max(1, min(limit, 5000)),),
            ).fetchall()

        return [self._event_from_row(row) for row in rows]

    def save_incident(self, incident: Incident) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, incident_type, risk_score, confidence, status,
                    created_at, detection_time, triage_time, recommendation_time,
                    scenario_id, related_event_ids_json, summary, recommendation, labels_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.incident_type,
                    incident.risk_score,
                    incident.confidence,
                    incident.status,
                    incident.created_at.isoformat(),
                    incident.detection_time.isoformat() if incident.detection_time else None,
                    incident.triage_time.isoformat() if incident.triage_time else None,
                    incident.recommendation_time.isoformat() if incident.recommendation_time else None,
                    incident.scenario_id,
                    json.dumps(incident.related_event_ids),
                    incident.summary,
                    incident.recommendation,
                    json.dumps(incident.labels, sort_keys=True),
                ),
            )

    def list_incidents(self, limit: int = 500) -> List[Incident]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM incidents ORDER BY detection_time DESC LIMIT ?",
                (max(1, min(limit, 5000)),),
            ).fetchall()

        return [self._incident_from_row(row) for row in rows]

    def clear_all(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM incidents")
            self._connection.execute("DELETE FROM events")

    def _event_from_row(self, row: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            event_id=row["event_id"],
            event_time=_parse_datetime(row["event_time"]),
            ingest_time=_parse_datetime(row["ingest_time"]),
            source=row["source"] or "gcp.auditlog",
            actor=row["actor"],
            action=row["action"],
            resource=row["resource"] or "unknown",
            source_ip=row["source_ip"],
            auth_success=(None if row["auth_success"] is None else bool(row["auth_success"])),
            bytes_out=row["bytes_out"] or 0,
            metadata=json.loads(row["metadata_json"] or "{}"),
            scenario_id=row["scenario_id"],
            is_attack=bool(row["is_attack"]),
        )

    def _incident_from_row(self, row: sqlite3.Row) -> Incident:
        return Incident(
            incident_id=row["incident_id"],
            incident_type=row["incident_type"],
            risk_score=row["risk_score"] or 0.0,
            confidence=row["confidence"] or 0.0,
            status=row["status"] or "open",
            created_at=_parse_datetime(row["created_at"]),
            detection_time=_parse_datetime(row["detection_time"]),
            triage_time=_parse_datetime(row["triage_time"]),
            recommendation_time=_parse_datetime(row["recommendation_time"]),
            scenario_id=row["scenario_id"],
            related_event_ids=json.loads(row["related_event_ids_json"] or "[]"),
            summary=row["summary"] or "",
            recommendation=row["recommendation"] or "",
            labels=json.loads(row["labels_json"] or "{}"),
        )
