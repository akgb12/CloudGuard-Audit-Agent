from __future__ import annotations

import argparse
from datetime import datetime
import json
from typing import Any, Dict, List

import requests


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _percentile(values: List[float], percentile: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = int((len(sorted_values) - 1) * percentile)
    return sorted_values[index]


def fetch_events(api_url: str, limit: int) -> List[Dict[str, Any]]:
    response = requests.get(f"{api_url.rstrip('/')}/events", params={"limit": limit}, timeout=10)
    response.raise_for_status()
    body = response.json()
    return body.get("events", [])


def fetch_incidents(api_url: str, limit: int) -> List[Dict[str, Any]]:
    response = requests.get(f"{api_url.rstrip('/')}/incidents", params={"limit": limit}, timeout=10)
    response.raise_for_status()
    body = response.json()
    return body.get("incidents", [])


def compute_metrics(
    events: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    alert_threshold: float = 45.0,
) -> Dict[str, Any]:
    scenarios: Dict[str, Dict[str, Any]] = {}

    for event in events:
        scenario_id = event.get("scenario_id")
        if not scenario_id:
            continue
        entry = scenarios.setdefault(scenario_id, {"events": [], "incidents": [], "is_attack": False})
        entry["events"].append(event)
        if bool(event.get("is_attack")):
            entry["is_attack"] = True

    for incident in incidents:
        scenario_id = incident.get("scenario_id")
        if not scenario_id or scenario_id not in scenarios:
            continue
        scenarios[scenario_id]["incidents"].append(incident)

    tp = fp = tn = fn = 0
    mttd_values: List[float] = []
    mttr_values: List[float] = []
    scenario_rows: List[Dict[str, Any]] = []

    for scenario_id, data in sorted(scenarios.items()):
        is_attack = bool(data["is_attack"])
        matching_incidents = []
        for incident in data["incidents"]:
            risk_score = float(incident.get("risk_score") or 0.0)
            if incident.get("status") != "suppressed" and risk_score >= alert_threshold:
                matching_incidents.append(incident)

        predicted_positive = bool(matching_incidents)

        if is_attack and predicted_positive:
            tp += 1
        elif is_attack and not predicted_positive:
            fn += 1
        elif not is_attack and predicted_positive:
            fp += 1
        else:
            tn += 1

        injection_times = []
        for event in data["events"]:
            parsed = _parse_datetime(event.get("event_time"))
            if parsed is not None:
                injection_times.append(parsed)

        detection_times = []
        recommendation_times = []
        for incident in matching_incidents:
            detected = _parse_datetime(incident.get("detection_time"))
            recommended = _parse_datetime(incident.get("recommendation_time"))
            if detected is not None:
                detection_times.append(detected)
            if recommended is not None:
                recommendation_times.append(recommended)

        scenario_mttd = None
        scenario_mttr = None
        if is_attack and injection_times and detection_times:
            first_injection = min(injection_times)
            first_detection = min(detection_times)
            scenario_mttd = (first_detection - first_injection).total_seconds()
            mttd_values.append(scenario_mttd)

            if recommendation_times:
                first_recommendation = min(recommendation_times)
                scenario_mttr = (first_recommendation - first_detection).total_seconds()
                mttr_values.append(scenario_mttr)

        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "is_attack": is_attack,
                "predicted_positive": predicted_positive,
                "incident_count": len(matching_incidents),
                "mttd_seconds": scenario_mttd,
                "mttr_seconds": scenario_mttr,
            }
        )

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "samples": {
            "scenarios": len(scenarios),
            "events": len(events),
            "incidents": len(incidents),
        },
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "mttd_seconds_mean": round(_mean(mttd_values), 2),
            "mttd_seconds_p50": round(_percentile(mttd_values, 0.50), 2),
            "mttd_seconds_p95": round(_percentile(mttd_values, 0.95), 2),
            "mttr_seconds_mean": round(_mean(mttr_values), 2),
            "mttr_seconds_p50": round(_percentile(mttr_values, 0.50), 2),
            "mttr_seconds_p95": round(_percentile(mttr_values, 0.95), 2),
        },
        "scenarios": scenario_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate CloudGuard detection metrics from API data")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument("--event-limit", type=int, default=5000)
    parser.add_argument("--incident-limit", type=int, default=5000)
    parser.add_argument("--alert-threshold", type=float, default=45.0)
    args = parser.parse_args()

    events = fetch_events(args.api_url, args.event_limit)
    incidents = fetch_incidents(args.api_url, args.incident_limit)
    report = compute_metrics(events, incidents, alert_threshold=args.alert_threshold)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
