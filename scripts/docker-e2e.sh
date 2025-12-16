#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG=${IMAGE_TAG:-comfyui-openai-api:e2e}
CONTAINER_NAME=${CONTAINER_NAME:-comfyui-openai-api-e2e}
API_PORT=${API_PORT:-8080}
COMFY_PORT=${COMFY_PORT:-8188}
STARTUP_TIMEOUT=${STARTUP_TIMEOUT:-180}

if ! command -v docker >/dev/null 2>&1; then
  echo "Skipping Docker E2E: docker command not found" >&2
  exit 0
fi

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Building image $IMAGE_TAG..."
docker build -t "$IMAGE_TAG" .

echo "Starting container $CONTAINER_NAME..."
docker run --gpus=all -d --rm \
  -p "${API_PORT}:8080" \
  -p "${COMFY_PORT}:8188" \
  --name "$CONTAINER_NAME" \
  "$IMAGE_TAG"

echo "Waiting for ComfyUI on port ${COMFY_PORT}..."
start_ts=$(date +%s)
while true; do
  if curl -fsS --max-time 5 "http://localhost:${COMFY_PORT}" >/dev/null 2>&1; then
    break
  fi
  if (( $(date +%s) - start_ts > STARTUP_TIMEOUT )); then
    echo "Timed out waiting for ComfyUI to start" >&2
    docker logs "$CONTAINER_NAME" || true
    exit 1
  fi
  sleep 2
done

echo "Waiting for proxy on port ${API_PORT}..."
while true; do
  proxy_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://localhost:${API_PORT}/health")
  if [[ "$proxy_status" == "200" ]]; then
    break
  fi
  if (( $(date +%s) - start_ts > STARTUP_TIMEOUT )); then
    echo "Timed out waiting for proxy to become responsive" >&2
    docker logs "$CONTAINER_NAME" || true
    exit 1
  fi
  sleep 2
done

echo "Docker E2E test passed: container built and services responded"
