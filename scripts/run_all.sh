#!/usr/bin/env bash
set -euo pipefail

# Optional: override config path via CONFIG_PATH env var
CONFIG_PATH="${CONFIG_PATH:-config/config.yaml}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

cleanup() {
  echo "Stopping FIM Agent processes..." >&2
  [[ -n "${AGENT_PID:-}" ]] && kill "${AGENT_PID}" 2>/dev/null || true
  [[ -n "${WEB_PID:-}" ]] && kill "${WEB_PID}" 2>/dev/null || true
}

trap cleanup SIGINT SIGTERM EXIT

python -m fim_agent.cli.main --config "${CONFIG_PATH}" run-agent &
AGENT_PID=$!

echo "run-agent started with PID ${AGENT_PID}" >&2

python -m fim_agent.cli.main --config "${CONFIG_PATH}" serve-web --host "${HOST}" --port "${PORT}" &
WEB_PID=$!

echo "serve-web started with PID ${WEB_PID}" >&2

wait "${AGENT_PID}" "${WEB_PID}"
