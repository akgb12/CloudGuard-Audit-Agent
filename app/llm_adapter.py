from __future__ import annotations

from typing import Any, Dict, Protocol

import requests

from app.config import Settings
from app.models import DetectionSignal, Incident, SecurityEvent


class LLMAdapter(Protocol):
    def summarize(self, event: SecurityEvent, incident: Incident, signal: DetectionSignal) -> str:
        ...


class TemplateLLMAdapter:
    def summarize(self, event: SecurityEvent, incident: Incident, signal: DetectionSignal) -> str:
        return (
            f"Detected {incident.incident_type} with confidence {incident.confidence:.2f}. "
            f"Actor {event.actor} performed action {event.action} on {event.resource}. "
            f"Rationale: {signal.rationale}."
        )


class HttpLLMAdapter:
    def __init__(self, url: str, api_key: str, model: str, fallback: TemplateLLMAdapter) -> None:
        self.url = url
        self.api_key = api_key
        self.model = model
        self.fallback = fallback

    def summarize(self, event: SecurityEvent, incident: Incident, signal: DetectionSignal) -> str:
        payload: Dict[str, Any] = {
            "task": "summarize_security_incident",
            "model": self.model,
            "event": event.model_dump(mode="json"),
            "incident": incident.model_dump(mode="json"),
            "signal": signal.model_dump(mode="json"),
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = requests.post(self.url, json=payload, headers=headers, timeout=8)
            response.raise_for_status()
            body = response.json()
            summary = body.get("summary") or body.get("output") or body.get("message")
            if isinstance(summary, str) and summary.strip():
                return summary.strip()
        except Exception:
            pass

        return self.fallback.summarize(event, incident, signal)


def build_llm_adapter(settings: Settings) -> LLMAdapter:
    fallback = TemplateLLMAdapter()
    if settings.llm_mode == "http" and settings.llm_http_url:
        return HttpLLMAdapter(settings.llm_http_url, settings.llm_api_key, settings.llm_model, fallback)
    return fallback
