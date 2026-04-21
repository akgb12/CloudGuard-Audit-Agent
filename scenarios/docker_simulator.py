from __future__ import annotations

import argparse
import time

from scenarios.scenario_runner import generate_scenario, send_events_http


def main() -> None:
    parser = argparse.ArgumentParser(description="Continuous local scenario simulator for Docker environments")
    parser.add_argument("--agent-url", default="http://cloudguard-agent:8080")
    parser.add_argument("--scenario", default="mixed")
    parser.add_argument("--interval-seconds", type=int, default=120)
    parser.add_argument("--pause-ms", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-cycles", type=int, default=0)
    args = parser.parse_args()

    cycle = 0
    while True:
        events = generate_scenario(args.scenario, seed=args.seed + cycle)
        send_events_http(events, args.agent_url, pause_ms=args.pause_ms)
        cycle += 1

        if args.max_cycles > 0 and cycle >= args.max_cycles:
            break

        time.sleep(max(1, args.interval_seconds))


if __name__ == "__main__":
    main()
