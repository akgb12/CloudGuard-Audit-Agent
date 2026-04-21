# CloudGuard LangChain SOC Agent

CloudGuard now runs a proper LangChain-based incident response agent with tools and persistent memory,
plus a local Docker simulation stack for cheap end-to-end testing.

## What This Implements

- FastAPI ingestion service for security events
- Deterministic detector layer (brute force, privilege escalation, exfiltration, public exposure, resource hijack)
- LangChain incident analyst agent with:
	- Tool calling for event context, related activity, historical incidents, MITRE mapping, and playbook lookup
	- Persistent conversation memory via SQLite-backed chat history
	- Structured security analysis output (summary, technical analysis, recommended actions, containment actions)
- Scenario generator and injector for benign and attack simulations
- Evaluation scripts for MTTD, MTTR, precision, recall, F1, false positive rate

## Architecture

1. Ingestion
- `POST /ingest/event` for direct local simulation events
- `POST /ingest/pubsub` for GCP Pub/Sub push payloads

2. Detection + Correlation
- Rule detections generate candidate incident signals
- Correlator groups related events in a time window

3. LangChain Incident Analysis
- Agent receives incident context
- Agent can call tools:
	- `get_current_event`
	- `get_related_events`
	- `get_historical_incidents`
	- `lookup_mitre`
	- `lookup_playbook`
- Agent memory is persisted in SQLite (`AGENT_MEMORY_SQLITE_PATH`)

4. Response Output
- Incident summary and technical analysis
- Immediate containment and response actions
- Risk adjustment applied to triage score

5. Evaluation
- Scripts compute confusion matrix and latency metrics for research reporting

## Project Layout

```
.
├── app/
│   ├── main.py
│   ├── pipeline.py
│   ├── llm_adapter.py
│   ├── detectors.py
│   ├── correlation.py
│   ├── triage.py
│   ├── response.py
│   ├── storage.py
│   ├── models.py
│   └── config.py
├── scenarios/
│   ├── scenario_runner.py
│   ├── docker_simulator.py
│   ├── evaluate.py
│   └── run_experiment.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

## Fastest Path: Docker Local Simulation

This runs everything locally:
- `ollama` for local LLM inference
- `cloudguard-agent` for API + LangChain orchestration
- optional `simulator` container for recurring attack/benign scenario injection

### 1) Start stack

```bash
docker compose up --build -d
```

Notes:
- First boot pulls Ollama model (`llama3.2:3b` by default), which can take time.
- API will be on `http://localhost:8000`.

### 2) Inject one mixed scenario locally

```bash
python -m scenarios.scenario_runner --scenario mixed --mode http --api-url http://localhost:8000
```

### 3) Inspect incidents

```bash
curl -s http://localhost:8000/incidents?limit=20 | jq
```

### 4) Compute metrics

```bash
python -m scenarios.evaluate --api-url http://localhost:8000
```

### 5) Optional continuous simulation container

```bash
docker compose --profile sim up -d simulator
```

## Non-Docker Local Run

Use this if you already have Python + Ollama installed locally.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export LLM_PROVIDER=ollama
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=llama3.2:3b
./scripts/run_local.sh
```

## LangChain Configuration

Primary env vars in `.env.example`:

- `LLM_PROVIDER=ollama|openai`
- `OLLAMA_BASE_URL=http://localhost:11434`
- `OLLAMA_MODEL=llama3.2:3b`
- `OPENAI_API_KEY=<optional>`
- `OPENAI_MODEL=gpt-4o-mini`
- `AGENT_MEMORY_SQLITE_PATH=/tmp/agent_memory.db`
- `LANGCHAIN_VERBOSE=false`

If `LLM_PROVIDER=openai` and key is set, agent uses OpenAI.
Otherwise it defaults to Ollama.

## Research Metrics Available

The evaluation pipeline currently outputs:

- TP, FP, TN, FN
- Precision, Recall, F1
- False Positive Rate
- MTTD mean/p50/p95 (seconds)
- MTTR mean/p50/p95 (seconds)
- Scenario-level detection details

Formulas:

- `MTTD = mean(detection_time - injection_time)`
- `MTTR = mean(recommendation_time - detection_time)`
- `FPR = FP / (FP + TN)`

## GCP Path (Optional)

If you still want Cloud Run + Pub/Sub later:

```bash
./scripts/deploy_gcp.sh <project-id> [region] [service-name] [topic-name] [subscription-name]
```

This local-first version is intentionally optimized for low-cost rapid iteration before cloud deployment.
