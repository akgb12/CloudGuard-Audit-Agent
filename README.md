# CloudGuard Audit Agent Prototype

CloudGuard is a basic agentic cloud security monitoring prototype for GCP free-tier experiments.
It ingests cloud-like telemetry events, detects suspicious behavior, correlates context, triages risk,
and recommends response actions.

This repository now includes:

- A runnable API service (FastAPI) for ingestion and triage
- A pluggable model adapter (agent-agnostic)
- Built-in rule detectors for baseline incidents
- Scenario injectors for benign and attack-like event streams
- Evaluation scripts that compute MTTD, MTTR, precision, recall, and false positive rate

## Architecture (Current MVP)

1. Event ingestion
- HTTP endpoint for direct event ingestion
- Pub/Sub push endpoint for GCP event transport

2. Detection and correlation
- Rule detectors: brute force, privilege escalation, data exfiltration, public exposure, resource hijack
- Correlation window for related events (actor/IP/resource/scenario grouping)

3. Agentic triage
- Risk scoring and confidence assignment
- MITRE ATT&CK label tagging
- Response recommendation planning
- Pluggable LLM adapter (template mode or external HTTP LLM endpoint)

4. Storage and analysis
- SQLite (default) or in-memory backend
- Event and incident retrieval APIs
- Evaluation scripts for concrete security metrics

## Project Layout

```
.
├── app/
│   ├── main.py                # API service entrypoint
│   ├── pipeline.py            # agent pipeline orchestration
│   ├── detectors.py           # detection rules
│   ├── correlation.py         # context correlation
│   ├── triage.py              # risk scoring + labels
│   ├── response.py            # response recommendations
│   ├── llm_adapter.py         # agent-agnostic LLM adapter
│   ├── storage.py             # SQLite/memory storage backends
│   ├── models.py              # event/incident schemas
│   └── config.py              # environment configuration
├── scenarios/
│   ├── scenario_runner.py     # inject benign + attack scenarios
│   ├── evaluate.py            # calculate MTTD/MTTR/FPR/etc.
│   └── run_experiment.py      # one-command benchmark run
├── scripts/
│   ├── run_local.sh           # local startup helper
│   └── deploy_gcp.sh          # Cloud Run + Pub/Sub setup
├── Dockerfile
├── requirements.txt
└── .env.example
```

## Local Quick Start

### 1) Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Run the API service

```bash
./scripts/run_local.sh
```

The service runs on http://localhost:8000.

### 3) Inject sample scenarios (HTTP mode)

```bash
python -m scenarios.scenario_runner --scenario mixed --mode http --api-url http://localhost:8000
```

### 4) Compute concrete metrics

```bash
python -m scenarios.evaluate --api-url http://localhost:8000
```

### 5) Run a full mini experiment in one command

```bash
python -m scenarios.run_experiment --api-url http://localhost:8000 --mode http --reset
```

## GCP Deployment (Free-Tier Friendly)

### Prerequisites

- gcloud CLI installed and authenticated
- GCP project with billing enabled
- Cloud Run, Cloud Build, and Pub/Sub APIs enabled (script will enable)

### Deploy to Cloud Run and connect Pub/Sub

```bash
./scripts/deploy_gcp.sh <project-id> [region] [service-name] [topic-name] [subscription-name]
```

Example:

```bash
./scripts/deploy_gcp.sh my-gcp-project us-central1 cloudguard-agent cloudguard-events cloudguard-events-push
```

After deployment, inject scenarios through Pub/Sub:

```bash
python -m scenarios.scenario_runner \
	--scenario mixed \
	--mode pubsub \
	--project-id <project-id> \
	--topic-id cloudguard-events
```

Then evaluate from the Cloud Run URL:

```bash
python -m scenarios.evaluate --api-url https://<cloud-run-url>
```

## Environment Variables

Copy .env.example and tune values as needed.

Key controls:

- `ALERT_MIN_RISK`: minimum score to keep incidents from being suppressed
- `BRUTE_FORCE_THRESHOLD`: failed auth attempts threshold
- `EXFIL_BYTES_THRESHOLD`: data transfer threshold in bytes
- `CORRELATION_WINDOW_SECONDS`: context window for related events

LLM adapter controls:

- `LLM_MODE=template` uses built-in deterministic summaries
- `LLM_MODE=http` uses `LLM_HTTP_URL` and optional `LLM_API_KEY` for model-generated summaries

## Concrete Metrics Produced

The evaluation script returns:

- Confusion matrix: TP, FP, TN, FN
- Precision, Recall, F1
- False Positive Rate
- MTTD mean/p50/p95 (seconds)
- MTTR mean/p50/p95 (seconds)
- Scenario-level detection breakdown

Definitions used:

- MTTD = mean(detection_time - injection_time)
- MTTR = mean(recommendation_time - detection_time)
- FPR = FP / (FP + TN)

## Notes and Next Iteration

This is a working MVP for rapid experimentation, not production security tooling.
Next improvements for research quality:

- Add Firestore/BigQuery backends for durable cloud-native storage
- Add repeated-run experiment harness with confidence intervals
- Add baseline-vs-agent comparison runner in one report
- Add dashboard export for paper-ready plots
