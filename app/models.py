from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_time: datetime = Field(default_factory=utc_now)
    ingest_time: Optional[datetime] = None
    source: str = "gcp.auditlog"
    actor: str
    action: str
    resource: str = "unknown"
    source_ip: Optional[str] = None
    auth_success: Optional[bool] = None
    bytes_out: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scenario_id: Optional[str] = None
    is_attack: bool = False


class DetectionSignal(BaseModel):
    incident_type: str
    severity_weight: int
    confidence: float
    rationale: str


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_type: str
    risk_score: float = 0.0
    confidence: float = 0.0
    status: str = "open"
    created_at: datetime = Field(default_factory=utc_now)
    detection_time: Optional[datetime] = None
    triage_time: Optional[datetime] = None
    recommendation_time: Optional[datetime] = None
    scenario_id: Optional[str] = None
    related_event_ids: List[str] = Field(default_factory=list)
    summary: str = ""
    recommendation: str = ""
    labels: Dict[str, str] = Field(default_factory=dict)
