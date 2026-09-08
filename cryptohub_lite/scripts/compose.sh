#!/usr/bin/env bash
#
# compose wrapper: resolves the container engine, then forwards everything to
# it with this project's compose file already selected.
#
#     scripts/compose.sh up -d --build
#     scripts/compose.sh logs -f api
#
# Exists so that callers which are not shell scripts — VS Code tasks, docs,
# muscle memory — do not each hardcode `docker compose`, which breaks on a
# Rancher Desktop set to containerd.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=engine.sh
. "$SCRIPT_DIR/engine.sh"
chl_require_engine

# $COMPOSE is unquoted on purpose: it may be two words ("docker compose").
exec $COMPOSE -f "$SCRIPT_DIR/../docker-compose.yml" "$@"
