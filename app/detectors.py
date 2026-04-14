from datetime import datetime
from typing import List

from app.config import Settings
from app.models import DetectionSignal, SecurityEvent


class DetectorEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        signals.extend(self._detect_bruteforce(event, recent_events))
        signals.extend(self._detect_privilege_escalation(event))
        signals.extend(self._detect_data_exfiltration(event))
        signals.extend(self._detect_public_exposure(event))
        signals.extend(self._detect_resource_hijack(event, recent_events))

        return signals

    def _detect_bruteforce(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[DetectionSignal]:
        if event.auth_success is not False or not event.source_ip:
            return []

        failed_attempts = 0
        for item in recent_events:
            if item.source_ip == event.source_ip and item.auth_success is False:
                failed_attempts += 1

        if failed_attempts >= self.settings.brute_force_threshold:
            return [
                DetectionSignal(
                    incident_type="credential_bruteforce",
                    severity_weight=4,
                    confidence=0.78,
                    rationale=(
                        f"Observed {failed_attempts} failed authentications from {event.source_ip} "
                        f"within the correlation window"
                    ),
                )
            ]
        return []

    def _detect_privilege_escalation(self, event: SecurityEvent) -> List[DetectionSignal]:
        suspicious_actions = {
            "iam.roles.create",
            "iam.roles.update",
            "iam.setIamPolicy",
            "resourcemanager.projects.setIamPolicy",
        }
        if event.action not in suspicious_actions:
            return []

        return [
            DetectionSignal(
                incident_type="privilege_escalation",
                severity_weight=5,
                confidence=0.82,
                rationale=f"Detected sensitive IAM action {event.action}",
            )
        ]

    def _detect_data_exfiltration(self, event: SecurityEvent) -> List[DetectionSignal]:
        external_destination = bool(event.metadata.get("external_destination"))
        if event.bytes_out < self.settings.exfil_bytes_threshold and not external_destination:
            return []

        if self._is_off_hours(event.event_time) or external_destination:
            reason = (
                f"Large data transfer detected ({event.bytes_out} bytes). "
                f"Off-hours={self._is_off_hours(event.event_time)}, external_destination={external_destination}"
            )
            return [
                DetectionSignal(
                    incident_type="data_exfiltration",
                    severity_weight=5,
                    confidence=0.75,
                    rationale=reason,
                )
            ]
        return []

    def _detect_public_exposure(self, event: SecurityEvent) -> List[DetectionSignal]:
        is_public_action = event.action in {
            "storage.buckets.setIamPolicy",
            "storage.buckets.setAcl",
        }
        became_public = bool(event.metadata.get("bucket_public"))
        if not is_public_action and not became_public:
            return []

        if became_public:
            return [
                DetectionSignal(
                    incident_type="public_resource_exposure",
                    severity_weight=4,
                    confidence=0.72,
                    rationale="A storage resource became publicly accessible",
                )
            ]
        return []

    def _detect_resource_hijack(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[DetectionSignal]:
        create_actions = {
            "compute.instances.insert",
            "compute.instances.start",
        }
        if event.action not in create_actions:
            return []

        burst_count = 0
        for item in recent_events:
            if item.actor == event.actor and item.action in create_actions:
                burst_count += 1

        if burst_count >= self.settings.resource_hijack_threshold:
            return [
                DetectionSignal(
                    incident_type="resource_hijack",
                    severity_weight=4,
                    confidence=0.74,
                    rationale=f"Rapid compute provisioning burst detected ({burst_count} actions)",
                )
            ]
        return []

    def _is_off_hours(self, timestamp: datetime) -> bool:
        hour = timestamp.hour
        start = self.settings.offhours_start
        end = self.settings.offhours_end

        if start > end:
            return hour >= start or hour < end
        return start <= hour < end
