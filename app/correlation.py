from datetime import timedelta
from typing import List

from app.models import DetectionSignal, Incident, SecurityEvent


class Correlator:
    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds

    def collect_related(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[SecurityEvent]:
        window_start = event.event_time - timedelta(seconds=self.window_seconds)
        related: List[SecurityEvent] = []

        for item in recent_events:
            if item.event_time < window_start:
                continue

            same_actor = item.actor == event.actor
            same_ip = bool(event.source_ip) and item.source_ip == event.source_ip
            same_resource = item.resource == event.resource
            same_scenario = bool(event.scenario_id) and item.scenario_id == event.scenario_id

            if same_actor or same_ip or same_resource or same_scenario:
                related.append(item)

        return related

    def build_incident(
        self,
        signal: DetectionSignal,
        event: SecurityEvent,
        related_events: List[SecurityEvent],
    ) -> Incident:
        event_ids = [item.event_id for item in related_events]
        if event.event_id not in event_ids:
            event_ids.append(event.event_id)

        return Incident(
            incident_type=signal.incident_type,
            scenario_id=event.scenario_id,
            related_event_ids=event_ids,
        )
