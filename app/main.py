from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query

from app.config import get_settings
from app.correlation import Correlator
from app.detectors import DetectorEngine
from app.llm_adapter import build_incident_analyst
from app.models import SecurityEvent
from app.pipeline import AgentPipeline
from app.response import ResponsePlanner
from app.storage import MemoryStore, SQLiteStore
from app.triage import TriageEngine


settings = get_settings()

if settings.store_backend == "memory":
    store = MemoryStore()
else:
    store = SQLiteStore(settings.sqlite_path)

pipeline = AgentPipeline(
    settings=settings,
    store=store,
    detectors=DetectorEngine(settings),
    correlator=Correlator(settings.correlation_window_seconds),
    triage=TriageEngine(),
    responder=ResponsePlanner(),
    analyst=build_incident_analyst(settings, store),
)

app = FastAPI(title="CloudGuard Agent Prototype", version="0.1.0")


@app.get("/")
def root() -> Dict[str, str]:
    return {"service": "cloudguard-agent", "status": "running"}


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/ingest/event")
def ingest_event(event: SecurityEvent) -> Dict[str, Any]:
    incidents = pipeline.process_event(event)
    return {
        "event_id": event.event_id,
        "incident_count": len(incidents),
        "incidents": [item.model_dump(mode="json") for item in incidents],
    }


@app.post("/ingest/pubsub")
def ingest_pubsub(payload: Dict[str, Any]) -> Dict[str, Any]:
    message = payload.get("message")
    if not isinstance(message, dict):
        raise HTTPException(status_code=400, detail="Missing Pub/Sub message envelope")

    encoded = message.get("data")
    if not isinstance(encoded, str):
        raise HTTPException(status_code=400, detail="Missing message.data")

    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
        event_payload = json.loads(decoded)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Pub/Sub payload: {exc}") from exc

    attributes = message.get("attributes") or {}
    if isinstance(attributes, dict) and "scenario_id" in attributes and "scenario_id" not in event_payload:
        event_payload["scenario_id"] = attributes["scenario_id"]

    event = SecurityEvent.model_validate(event_payload)
    incidents = pipeline.process_event(event)

    return {
        "event_id": event.event_id,
        "incident_count": len(incidents),
        "incidents": [item.model_dump(mode="json") for item in incidents],
    }


@app.get("/events")
def list_events(limit: int = Query(default=200, ge=1, le=5000)) -> Dict[str, Any]:
    items = store.list_events(limit=limit)
    return {
        "count": len(items),
        "events": [item.model_dump(mode="json") for item in items],
    }


@app.get("/incidents")
def list_incidents(limit: int = Query(default=200, ge=1, le=5000)) -> Dict[str, Any]:
    items = store.list_incidents(limit=limit)
    return {
        "count": len(items),
        "incidents": [item.model_dump(mode="json") for item in items],
    }


@app.post("/admin/reset")
def reset_all() -> Dict[str, str]:
    store.clear_all()
    return {"status": "reset"}
