from datetime import datetime, timedelta, timezone
from typing import List

from app.config import Settings
from app.correlation import Correlator
from app.detectors import DetectorEngine
from app.llm_adapter import LLMAdapter
from app.models import Incident, SecurityEvent
from app.response import ResponsePlanner
from app.storage import Store
from app.triage import TriageEngine


class AgentPipeline:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        detectors: DetectorEngine,
        correlator: Correlator,
        triage: TriageEngine,
        responder: ResponsePlanner,
        llm: LLMAdapter,
    ) -> None:
        self.settings = settings
        self.store = store
        self.detectors = detectors
        self.correlator = correlator
        self.triage = triage
        self.responder = responder
        self.llm = llm

    def process_event(self, event: SecurityEvent) -> List[Incident]:
        now = datetime.now(timezone.utc)
        event.ingest_time = now
        self.store.save_event(event)

        since = event.event_time - timedelta(seconds=self.settings.correlation_window_seconds)
        recent_events = self.store.get_recent_events(
            since=since,
            actor=event.actor,
            source_ip=event.source_ip,
            resource=event.resource,
            limit=1000,
        )

        signals = self.detectors.evaluate(event, recent_events)
        incidents: List[Incident] = []

        for signal in signals:
            related_events = self.correlator.collect_related(event, recent_events)
            incident = self.correlator.build_incident(signal, event, related_events)

            triage_result = self.triage.assess(signal, event, related_events)
            incident.risk_score = float(triage_result["risk_score"])
            incident.confidence = float(triage_result["confidence"])
            incident.labels = dict(triage_result["labels"])
            incident.detection_time = datetime.now(timezone.utc)
            incident.triage_time = datetime.now(timezone.utc)
            incident.recommendation = self.responder.recommend(incident.incident_type, incident.risk_score, event)
            incident.recommendation_time = datetime.now(timezone.utc)
            incident.summary = self.llm.summarize(event, incident, signal)

            if incident.risk_score < self.settings.alert_min_risk:
                incident.status = "suppressed"

            self.store.save_incident(incident)
            incidents.append(incident)

        return incidents
