from typing import Dict, List

from app.models import DetectionSignal, SecurityEvent


MITRE_MAP = {
    "credential_bruteforce": {"tactic": "TA0006", "technique": "T1110"},
    "privilege_escalation": {"tactic": "TA0004", "technique": "T1098"},
    "data_exfiltration": {"tactic": "TA0010", "technique": "T1020"},
    "public_resource_exposure": {"tactic": "TA0005", "technique": "T1562"},
    "resource_hijack": {"tactic": "TA0040", "technique": "T1496"},
}


class TriageEngine:
    def assess(
        self,
        signal: DetectionSignal,
        event: SecurityEvent,
        related_events: List[SecurityEvent],
    ) -> Dict[str, object]:
        score = float(signal.severity_weight * 14)

        if len(related_events) >= 4:
            score += 10.0
        if event.metadata.get("threat_intel_hit"):
            score += 15.0
        if event.metadata.get("external_destination"):
            score += 8.0
        if event.is_attack:
            # This label is only present in synthetic experiments and helps in evaluation runs.
            score += 6.0

        score = max(0.0, min(score, 100.0))
        confidence = min(0.99, signal.confidence + min(len(related_events) * 0.02, 0.2))

        mapping = MITRE_MAP.get(signal.incident_type, {"tactic": "unknown", "technique": "unknown"})
        labels = {
            "mitre_tactic": mapping["tactic"],
            "mitre_technique": mapping["technique"],
            "source": event.source,
        }

        return {
            "risk_score": round(score, 2),
            "confidence": round(confidence, 3),
            "labels": labels,
        }
