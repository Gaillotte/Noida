#!/usr/bin/env bash
#
# One-command bootstrap for IDEMIA CryptoHub Lite.
#
# Checks prerequisites, builds the images, starts the stack and waits until it
# is genuinely serving — not merely started. Safe to re-run: everything it does
# is idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="$ROOT/cryptohub_lite/docker-compose.yml"

info()  { printf '\033[0;36m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[0;32m  ok\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31merror\033[0m %s\n' "$*" >&2; exit 1; }

info "Checking prerequisites"
command -v docker >/dev/null 2>&1 || fail "Docker is required but was not found on PATH."
docker info >/dev/null 2>&1 || fail "Docker is installed but not running. Start Docker Desktop and retry."
ok "Docker is available"

info "Building images (SoftHSM2 is compiled from source; first run takes a few minutes)"
docker compose -f "$COMPOSE" build

info "Starting the stack"
docker compose -f "$COMPOSE" up -d

info "Waiting for the API to report healthy"
for attempt in $(seq 1 60); do
    if curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then
        ok "API is serving"
        break
    fi
    if [ "$attempt" -eq 60 ]; then
        fail "API did not become healthy. Inspect: docker compose -f $COMPOSE logs api"
    fi
    sleep 2
done

health="$(curl -fsS http://localhost:8000/api/health)"
echo "$health" | grep -q '"hsm_available":true' \
    && ok "HSM token is available" \
    || printf '\033[0;33m  warn\033[0m HSM is not available; check: docker compose -f %s logs api\n' "$COMPOSE"

cat <<BANNER

  IDEMIA CryptoHub Lite is running.

    Portal      http://localhost:8081       admin / admin
    REST API    http://localhost:8000/api/docs
    KMIP        localhost:5697              (5696 inside the network)
    PostgreSQL  localhost:5432              cryptohub / devpass

  Change the bootstrap administrator password before doing anything else:
  Administration -> Users.

BANNER
