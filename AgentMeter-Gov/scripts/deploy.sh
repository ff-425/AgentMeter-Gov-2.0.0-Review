#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Set production secrets, then run again." >&2
  exit 1
fi

docker compose up -d --build
echo "AgentMeter-Gov is available at http://127.0.0.1:8765"
