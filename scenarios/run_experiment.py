from __future__ import annotations

import argparse
import json
import requests

from scenarios import evaluate
from scenarios import scenario_runner


def run_experiment(
    api_url: str,
    mode: str,
    project_id: str,
    topic_id: str,
    seed: int,
    pause_ms: int,
    reset: bool,
    alert_threshold: float,
) -> dict:
    if reset:
        response = requests.post(f"{api_url.rstrip('/')}/admin/reset", timeout=10)
        response.raise_for_status()

    scenario_plan = [
        ("benign", 80),
        ("brute-force", 0),
        ("privilege-escalation", 0),
        ("data-exfiltration", 0),
        ("public-exposure", 0),
        ("resource-hijack", 0),
    ]

    total_events = 0
    for offset, (name, benign_count) in enumerate(scenario_plan):
        events = scenario_runner.generate_scenario(name, benign_count=benign_count, seed=seed + offset)
        total_events += len(events)
        if mode == "http":
            scenario_runner.send_events_http(events, api_url, pause_ms=pause_ms)
        else:
            scenario_runner.send_events_pubsub(events, project_id=project_id, topic_id=topic_id, pause_ms=pause_ms)

    events = evaluate.fetch_events(api_url, 5000)
    incidents = evaluate.fetch_incidents(api_url, 5000)
    report = evaluate.compute_metrics(events, incidents, alert_threshold=alert_threshold)
    report["experiment"] = {
        "mode": mode,
        "total_injected_events": total_events,
        "seed": seed,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run basic benchmark scenarios and print metrics")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument("--mode", choices=["http", "pubsub"], default="http")
    parser.add_argument("--project-id", default="")
    parser.add_argument("--topic-id", default="cloudguard-events")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--pause-ms", type=int, default=50)
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--alert-threshold", type=float, default=45.0)
    args = parser.parse_args()

    if args.mode == "pubsub" and not args.project_id:
        raise ValueError("--project-id is required for pubsub mode")

    report = run_experiment(
        api_url=args.api_url,
        mode=args.mode,
        project_id=args.project_id,
        topic_id=args.topic_id,
        seed=args.seed,
        pause_ms=args.pause_ms,
        reset=args.reset,
        alert_threshold=args.alert_threshold,
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
