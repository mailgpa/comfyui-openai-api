#!/usr/bin/env bash
set -euo pipefail

COMFY_HOST=${COMFY_HOST:-0.0.0.0}
COMFY_PORT=${COMFY_PORT:-8188}
CONFIG_PATH=${CONFIG_PATH:-/app/config/config.yaml}

mkdir -p /app/workflows /app/config

cleanup() {
  if [[ -n "${COMFY_PID:-}" ]]; then
    kill "$COMFY_PID" 2>/dev/null || true
  fi
  if [[ -n "${API_PID:-}" ]]; then
    kill "$API_PID" 2>/dev/null || true
  fi
}

trap cleanup INT TERM

comfy-cli launch -- --listen "${COMFY_HOST}" --port "${COMFY_PORT}" &
COMFY_PID=$!

for _ in $(seq 1 60); do
  if nc -z localhost "${COMFY_PORT}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

/app/bin/comfyui-openai-api &
API_PID=$!

wait -n "$COMFY_PID" "$API_PID"
EXIT_CODE=$?
cleanup
exit "$EXIT_CODE"
