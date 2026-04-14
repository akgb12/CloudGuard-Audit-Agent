#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${1:-}"
REGION="${2:-us-central1}"
SERVICE_NAME="${3:-cloudguard-agent}"
TOPIC_NAME="${4:-cloudguard-events}"
SUBSCRIPTION_NAME="${5:-cloudguard-events-push}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "Usage: ./scripts/deploy_gcp.sh <project-id> [region] [service-name] [topic-name] [subscription-name]"
  exit 1
fi

echo "[1/6] Configuring gcloud project"
gcloud config set project "$PROJECT_ID"

echo "[2/6] Enabling required services"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com pubsub.googleapis.com

echo "[3/6] Ensuring Pub/Sub topic exists"
if ! gcloud pubsub topics describe "$TOPIC_NAME" >/dev/null 2>&1; then
  gcloud pubsub topics create "$TOPIC_NAME"
fi

echo "[4/6] Building container image"
gcloud builds submit --tag "gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "[5/6] Deploying Cloud Run service"
gcloud run deploy "$SERVICE_NAME" \
  --image "gcr.io/${PROJECT_ID}/${SERVICE_NAME}" \
  --platform managed \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "APP_ENV=prod,STORE_BACKEND=sqlite,SQLITE_PATH=/tmp/cloudguard.db"

SERVICE_URL="$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format='value(status.url)')"
PUSH_ENDPOINT="${SERVICE_URL}/ingest/pubsub"

echo "[6/6] Ensuring Pub/Sub push subscription exists"
if gcloud pubsub subscriptions describe "$SUBSCRIPTION_NAME" >/dev/null 2>&1; then
  gcloud pubsub subscriptions modify-push-config "$SUBSCRIPTION_NAME" \
    --push-endpoint "$PUSH_ENDPOINT"
else
  gcloud pubsub subscriptions create "$SUBSCRIPTION_NAME" \
    --topic "$TOPIC_NAME" \
    --push-endpoint "$PUSH_ENDPOINT" \
    --ack-deadline 30
fi

echo "Deployment complete"
echo "Cloud Run URL: $SERVICE_URL"
echo "Pub/Sub topic: $TOPIC_NAME"
echo "Pub/Sub subscription: $SUBSCRIPTION_NAME"
