from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Dict, List, Protocol

from langchain.agents import AgentType, initialize_agent
from langchain.memory import ConversationBufferMemory
from langchain.tools import Tool
from langchain_community.chat_message_histories import SQLChatMessageHistory
from langchain_google_genai import ChatGoogleGenerativeAI

from app.config import Settings
from app.models import DetectionSignal, Incident, SecurityEvent
from app.storage import Store


MITRE_LOOKUP = {
    "credential_bruteforce": {
        "tactic": "TA0006 Credential Access",
        "technique": "T1110 Brute Force",
    },
    "privilege_escalation": {
        "tactic": "TA0004 Privilege Escalation",
        "technique": "T1098 Account Manipulation",
    },
    "data_exfiltration": {
        "tactic": "TA0010 Exfiltration",
        "technique": "T1020 Automated Exfiltration",
    },
    "public_resource_exposure": {
        "tactic": "TA0005 Defense Evasion",
        "technique": "T1562 Impair Defenses",
    },
    "resource_hijack": {
        "tactic": "TA0040 Impact",
        "technique": "T1496 Resource Hijacking",
    },
}

PLAYBOOK_LOOKUP = {
    "credential_bruteforce": [
        "Block source IP at perimeter and identity-aware proxy",
        "Force credential reset and require MFA re-enrollment",
        "Inspect recent successful logins for compromised sessions",
    ],
    "privilege_escalation": [
        "Revert IAM policy delta and disable modified principal",
        "Audit all IAM changes performed by the actor in the last 24h",
        "Collect policy diff artifacts for post-incident review",
    ],
    "data_exfiltration": [
        "Revoke active tokens and isolate impacted service account",
        "Block destination endpoint and rotate affected secrets",
        "Preserve transfer logs for forensic chain of custody",
    ],
    "public_resource_exposure": [
        "Reapply private ACL and enforce bucket policy guardrails",
        "Scan storage inventory for public object exposure",
        "Enable alerting on future policy drift events",
    ],
    "resource_hijack": [
        "Suspend burst compute instances and snapshot evidence",
        "Rotate credentials for automation identities",
        "Review billing and quota anomalies for abuse scope",
    ],
}


@dataclass
class AgentAnalysis:
    summary: str
    technical_analysis: str
    recommended_actions: List[str]
    containment_actions: List[str]
    confidence_reasoning: str
    risk_adjustment: float

    @classmethod
    def from_json_dict(cls, payload: Dict[str, Any]) -> AgentAnalysis:
        raw_actions = payload.get("recommended_actions", [])
        if not isinstance(raw_actions, list):
            raw_actions = [raw_actions]

        raw_containment = payload.get("containment_actions", [])
        if not isinstance(raw_containment, list):
            raw_containment = [raw_containment]

        try:
            risk_adjustment = float(payload.get("risk_adjustment", 0.0))
        except (TypeError, ValueError):
            risk_adjustment = 0.0

        return cls(
            summary=str(payload.get("summary", "No summary generated.")).strip(),
            technical_analysis=str(payload.get("technical_analysis", "No technical analysis generated.")).strip(),
            recommended_actions=[str(item).strip() for item in raw_actions if str(item).strip()],
            containment_actions=[str(item).strip() for item in raw_containment if str(item).strip()],
            confidence_reasoning=str(payload.get("confidence_reasoning", "No confidence reasoning provided.")).strip(),
            risk_adjustment=risk_adjustment,
        )


class IncidentAnalyst(Protocol):
    def analyze(
        self,
        event: SecurityEvent,
        incident: Incident,
        signal: DetectionSignal,
        related_events: List[SecurityEvent],
    ) -> AgentAnalysis:
        ...


def _extract_json_object(text: str) -> Dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}

    candidate = text[start : end + 1]
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        return {}
    return {}


class DeterministicAnalyst:
    def analyze(
        self,
        event: SecurityEvent,
        incident: Incident,
        signal: DetectionSignal,
        related_events: List[SecurityEvent],
    ) -> AgentAnalysis:
        mitre = MITRE_LOOKUP.get(incident.incident_type, {"tactic": "unknown", "technique": "unknown"})
        playbook = PLAYBOOK_LOOKUP.get(incident.incident_type, ["Open incident for analyst validation"])
        burst_signal = "high" if len(related_events) >= 6 else "moderate"

        summary = (
            f"{incident.incident_type} detected for actor {event.actor} on {event.resource}; "
            f"observed confidence {incident.confidence:.2f} with {len(related_events)} related events."
        )
        technical_analysis = (
            f"Mapped to {mitre['tactic']} / {mitre['technique']}. "
            f"Signal rationale: {signal.rationale}. Correlation burst level: {burst_signal}."
        )

        containment_actions = playbook[:2]
        recommended_actions = playbook
        if event.metadata.get("external_destination"):
            recommended_actions.append("Block egress route and verify destination ownership")

        return AgentAnalysis(
            summary=summary,
            technical_analysis=technical_analysis,
            recommended_actions=recommended_actions,
            containment_actions=containment_actions,
            confidence_reasoning=f"Base confidence={signal.confidence:.2f}; related_events={len(related_events)}",
            risk_adjustment=6.0 if len(related_events) >= 4 else 2.0,
        )

class LangChainIncidentAnalyst:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        self.fallback = DeterministicAnalyst()
        self.model = self._build_model()

    def _build_model(self):
        return ChatGoogleGenerativeAI(
            google_api_key=self.settings.gemini_api_key,
            model=self.settings.gemini_model,
            temperature=0.1,
            timeout=20,
        )

    def _build_memory(self, session_id: str) -> ConversationBufferMemory:
        history = SQLChatMessageHistory(
            session_id=session_id,
            connection_string=f"sqlite:///{self.settings.agent_memory_sqlite_path}",
        )
        return ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True,
            chat_memory=history,
            input_key="input",
        )

    def _build_tools(self, context: Dict[str, Any]) -> List[Tool]:
        def get_current_event(_: str = "") -> str:
            payload = {
                "event": context["event"],
                "incident": context["incident"],
                "signal": context["signal"],
            }
            return json.dumps(payload, indent=2)

        def get_related_events(raw_limit: str = "8") -> str:
            try:
                limit = max(1, min(int(raw_limit.strip() or "8"), 25))
            except ValueError:
                limit = 8
            return json.dumps(context["related_events"][:limit], indent=2)

        def get_historical_incidents(incident_type: str) -> str:
            selected_type = incident_type.strip() or context["incident"]["incident_type"]
            history = []
            for item in self.store.list_incidents(limit=100):
                if item.incident_type != selected_type:
                    continue
                history.append(
                    {
                        "incident_id": item.incident_id,
                        "risk_score": item.risk_score,
                        "confidence": item.confidence,
                        "status": item.status,
                        "summary": item.summary,
                    }
                )
                if len(history) >= 8:
                    break
            return json.dumps(history, indent=2)

        def lookup_mitre(incident_type: str) -> str:
            key = incident_type.strip() or context["incident"]["incident_type"]
            mapping = MITRE_LOOKUP.get(key, {"tactic": "unknown", "technique": "unknown"})
            return json.dumps(mapping, indent=2)

        def lookup_playbook(incident_type: str) -> str:
            key = incident_type.strip() or context["incident"]["incident_type"]
            steps = PLAYBOOK_LOOKUP.get(key, ["Open incident for analyst validation"])
            return json.dumps(steps, indent=2)

        return [
            Tool.from_function(
                name="get_current_event",
                func=get_current_event,
                description=(
                    "Get the full current event and incident context JSON. "
                    "Input ignored. Use this first."
                ),
            ),
            Tool.from_function(
                name="get_related_events",
                func=get_related_events,
                description=(
                    "Get related events as JSON. Input is integer limit as string, for example '8'."
                ),
            ),
            Tool.from_function(
                name="get_historical_incidents",
                func=get_historical_incidents,
                description=(
                    "Get prior incidents for a specific incident type. "
                    "Input should be incident type string."
                ),
            ),
            Tool.from_function(
                name="lookup_mitre",
                func=lookup_mitre,
                description="Lookup MITRE tactic and technique for an incident type.",
            ),
            Tool.from_function(
                name="lookup_playbook",
                func=lookup_playbook,
                description="Lookup playbook actions for an incident type.",
            ),
        ]

    def _build_prompt(self, context: Dict[str, Any]) -> str:
        return (
            "You are CloudGuard SOC analyst agent. "
            "Use tools before answering. Generate a concise but actionable incident analysis.\n"
            "Return JSON only with this schema:\n"
            "{\n"
            '  "summary": "string",\n'
            '  "technical_analysis": "string",\n'
            '  "recommended_actions": ["string"],\n'
            '  "containment_actions": ["string"],\n'
            '  "confidence_reasoning": "string",\n'
            '  "risk_adjustment": number\n'
            "}\n"
            "Rules:\n"
            "- risk_adjustment must be between -15 and +15.\n"
            "- recommended_actions must include at least 3 concrete steps.\n"
            "- containment_actions must include immediate actions executable in <= 15 minutes.\n"
            "- Do not include markdown. JSON only.\n"
            f"Current incident type: {context['incident']['incident_type']}"
        )

    def analyze(
        self,
        event: SecurityEvent,
        incident: Incident,
        signal: DetectionSignal,
        related_events: List[SecurityEvent],
    ) -> AgentAnalysis:
        context = {
            "event": event.model_dump(mode="json"),
            "incident": incident.model_dump(mode="json"),
            "signal": signal.model_dump(mode="json"),
            "related_events": [item.model_dump(mode="json") for item in related_events],
        }

        session_id = incident.scenario_id or f"actor:{event.actor}"
        memory = self._build_memory(session_id)
        tools = self._build_tools(context)

        try:
            agent = initialize_agent(
                tools=tools,
                llm=self.model,
                agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
                memory=memory,
                verbose=self.settings.langchain_verbose,
                max_iterations=6,
                handle_parsing_errors=True,
            )
            result = agent.invoke({"input": self._build_prompt(context)})
            output = result.get("output", "") if isinstance(result, dict) else str(result)
            payload = _extract_json_object(output)
            if payload:
                analysis = AgentAnalysis.from_json_dict(payload)
                analysis.risk_adjustment = max(-15.0, min(15.0, analysis.risk_adjustment))
                if analysis.recommended_actions:
                    return analysis
        except Exception:
            pass

        return self.fallback.analyze(event, incident, signal, related_events)


def build_incident_analyst(settings: Settings, store: Store) -> IncidentAnalyst:
    return LangChainIncidentAnalyst(settings=settings, store=store)
