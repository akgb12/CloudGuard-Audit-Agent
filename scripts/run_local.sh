#!/usr/bin/env bash
set -euo pipefail

export APP_ENV="${APP_ENV:-dev}"
export STORE_BACKEND="${STORE_BACKEND:-sqlite}"
export SQLITE_PATH="${SQLITE_PATH:-/tmp/cloudguard.db}"
export PORT="${PORT:-8000}"

uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --reload
