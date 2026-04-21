from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import random
import time
from typing import Dict, List
from uuid import uuid4

import requests

try:
    from google.cloud import pubsub_v1
except ImportError:  # pragma: no cover
    pubsub_v1 = None


BENIGN_ACTIONS = [
    "compute.instances.list",
    "storage.objects.get",
    "bigquery.jobs.query",
    "cloudfunctions.functions.get",
]


def _iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _new_scenario_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:8]}"


def _event(
    event_time: datetime,
    actor: str,
    action: str,
    resource: str,
    source_ip: str,
    scenario_id: str,
    is_attack: bool,
    auth_success: bool | None = None,
    bytes_out: int = 0,
    metadata: Dict[str, object] | None = None,
) -> Dict[str, object]:
    return {
        "event_time": _iso_time(event_time),
        "source": "gcp.auditlog",
        "actor": actor,
        "action": action,
        "resource": resource,
        "source_ip": source_ip,
        "auth_success": auth_success,
        "bytes_out": bytes_out,
        "scenario_id": scenario_id,
        "is_attack": is_attack,
        "metadata": metadata or {},
    }


def build_benign_events(count: int, start_time: datetime, scenario_id: str | None = None) -> List[Dict[str, object]]:
    scenario_id = scenario_id or _new_scenario_id("benign")
    events: List[Dict[str, object]] = []
    for index in range(count):
        action = random.choice(BENIGN_ACTIONS)
        actor = random.choice(["dev-alice", "dev-bob", "service-api", "analyst-jane"])
        source_ip = f"10.0.0.{random.randint(2, 50)}"
        event_time = start_time + timedelta(seconds=index * 2)
        events.append(
            _event(
                event_time=event_time,
                actor=actor,
                action=action,
                resource="projects/demo/resources/default",
                source_ip=source_ip,
                scenario_id=scenario_id,
                is_attack=False,
                auth_success=True,
                bytes_out=random.randint(5000, 500000),
            )
        )
    return events


def build_bruteforce_events(start_time: datetime, scenario_id: str | None = None) -> List[Dict[str, object]]:
    scenario_id = scenario_id or _new_scenario_id("brute-force")
    events: List[Dict[str, object]] = []
    attack_ip = "185.199.110.51"
    for index in range(12):
        events.append(
            _event(
                event_time=start_time + timedelta(seconds=index * 5),
                actor="unknown-user",
                action="iam.login",
                resource="projects/demo/users/finance-admin",
                source_ip=attack_ip,
                scenario_id=scenario_id,
                is_attack=True,
                auth_success=False,
            )
        )
    return events


def build_privilege_escalation_events(start_time: datetime, scenario_id: str | None = None) -> List[Dict[str, object]]:
    scenario_id = scenario_id or _new_scenario_id("priv-esc")
    return [
        _event(
            event_time=start_time,
            actor="service-build",
            action="iam.roles.create",
            resource="projects/demo/roles/customAttackRole",
            source_ip="10.0.0.20",
            scenario_id=scenario_id,
            is_attack=True,
        ),
        _event(
            event_time=start_time + timedelta(seconds=20),
            actor="service-build",
            action="iam.setIamPolicy",
            resource="projects/demo",
            source_ip="10.0.0.20",
            scenario_id=scenario_id,
            is_attack=True,
        ),
    ]


def build_exfiltration_events(start_time: datetime, scenario_id: str | None = None) -> List[Dict[str, object]]:
    scenario_id = scenario_id or _new_scenario_id("exfil")
    return [
        _event(
            event_time=start_time,
            actor="service-storage",
            action="storage.objects.get",
            resource="projects/demo/buckets/customer-data",
            source_ip="34.100.8.8",
            scenario_id=scenario_id,
            is_attack=True,
            bytes_out=500 * 1024 * 1024,
            metadata={"external_destination": True, "destination": "external-bucket"},
        )
    ]


def build_public_exposure_events(start_time: datetime, scenario_id: str | None = None) -> List[Dict[str, object]]:
    scenario_id = scenario_id or _new_scenario_id("public")
    return [
        _event(
            event_time=start_time,
            actor="dev-alice",
            action="storage.buckets.setIamPolicy",
            resource="projects/demo/buckets/private-backups",
            source_ip="10.0.0.9",
            scenario_id=scenario_id,
            is_attack=True,
            metadata={"bucket_public": True},
        )
    ]


def build_resource_hijack_events(start_time: datetime, scenario_id: str | None = None) -> List[Dict[str, object]]:
    scenario_id = scenario_id or _new_scenario_id("resource-hijack")
    events: List[Dict[str, object]] = []
    for index in range(15):
        events.append(
            _event(
                event_time=start_time + timedelta(seconds=index * 3),
                actor="service-ml",
                action="compute.instances.insert",
                resource=f"projects/demo/zones/us-central1-a/instances/gpu-{index}",
                source_ip="10.0.0.77",
                scenario_id=scenario_id,
                is_attack=True,
            )
        )
    return events


def generate_scenario(name: str, benign_count: int = 60, seed: int = 42) -> List[Dict[str, object]]:
    random.seed(seed)
    start_time = datetime.now(timezone.utc)

    if name == "benign":
        return build_benign_events(benign_count, start_time)
    if name == "brute-force":
        return build_bruteforce_events(start_time)
    if name == "privilege-escalation":
        return build_privilege_escalation_events(start_time)
    if name == "data-exfiltration":
        return build_exfiltration_events(start_time)
    if name == "public-exposure":
        return build_public_exposure_events(start_time)
    if name == "resource-hijack":
        return build_resource_hijack_events(start_time)
    if name == "mixed":
        events: List[Dict[str, object]] = []
        events.extend(build_benign_events(benign_count, start_time, _new_scenario_id("benign")))
        events.extend(build_bruteforce_events(start_time + timedelta(seconds=120)))
        events.extend(build_privilege_escalation_events(start_time + timedelta(seconds=220)))
        events.extend(build_exfiltration_events(start_time + timedelta(seconds=280)))
        events.extend(build_public_exposure_events(start_time + timedelta(seconds=320)))
        events.extend(build_resource_hijack_events(start_time + timedelta(seconds=360)))
        events.sort(key=lambda item: str(item["event_time"]))
        return events

    raise ValueError(f"Unsupported scenario: {name}")


def send_events_http(
    events: List[Dict[str, object]],
    api_url: str,
    pause_ms: int = 0,
    request_timeout_seconds: int = 30,
    max_retries: int = 2,
) -> None:
    ingest_url = f"{api_url.rstrip('/')}/ingest/event"
    for event in events:
        attempts = 0
        while True:
            try:
                response = requests.post(ingest_url, json=event, timeout=request_timeout_seconds)
                response.raise_for_status()
                break
            except requests.exceptions.ReadTimeout:
                if attempts >= max_retries:
                    raise
                attempts += 1
        if pause_ms > 0:
            time.sleep(pause_ms / 1000.0)


def send_events_pubsub(
    events: List[Dict[str, object]],
    project_id: str,
    topic_id: str,
    pause_ms: int = 0,
) -> None:
    if pubsub_v1 is None:
        raise RuntimeError("google-cloud-pubsub is not installed")

    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project_id, topic_id)
    futures = []
    for event in events:
        payload = json.dumps(event).encode("utf-8")
        attributes = {
            "scenario_id": str(event.get("scenario_id") or ""),
            "is_attack": str(bool(event.get("is_attack"))).lower(),
        }
        futures.append(publisher.publish(topic_path, payload, **attributes))
        if pause_ms > 0:
            time.sleep(pause_ms / 1000.0)

    for future in futures:
        future.result(timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject security scenarios into CloudGuard")
    parser.add_argument(
        "--scenario",
        choices=[
            "benign",
            "brute-force",
            "privilege-escalation",
            "data-exfiltration",
            "public-exposure",
            "resource-hijack",
            "mixed",
        ],
        default="mixed",
    )
    parser.add_argument("--mode", choices=["http", "pubsub"], default="http")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument("--project-id", default="")
    parser.add_argument("--topic-id", default="cloudguard-events")
    parser.add_argument("--benign-count", type=int, default=60)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--pause-ms", type=int, default=50)
    parser.add_argument("--request-timeout-seconds", type=int, default=30)
    parser.add_argument("--max-retries", type=int, default=2)
    args = parser.parse_args()

    events = generate_scenario(args.scenario, benign_count=args.benign_count, seed=args.seed)

    if args.mode == "http":
        send_events_http(
            events,
            args.api_url,
            pause_ms=args.pause_ms,
            request_timeout_seconds=args.request_timeout_seconds,
            max_retries=args.max_retries,
        )
    else:
        if not args.project_id:
            raise ValueError("--project-id is required for Pub/Sub mode")
        send_events_pubsub(events, args.project_id, args.topic_id, pause_ms=args.pause_ms)

    scenario_ids = sorted({str(event.get("scenario_id")) for event in events if event.get("scenario_id")})
    print(json.dumps({"injected_events": len(events), "scenario_ids": scenario_ids}, indent=2))


if __name__ == "__main__":
    main()
