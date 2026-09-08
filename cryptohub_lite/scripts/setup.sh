#!/usr/bin/env bash
#
# Single entry point for IDEMIA CryptoHub Lite.
#
# Everything that manages the stack lives here, including the volume backup
# that used to be a separate backup.cmd. One script means one place to learn,
# one place that resolves the container engine, and no second copy of the
# project and volume names to fall out of step.
#
#   setup                    build, start, and wait until it is serving
#   setup up                 same
#   setup down               stop and remove containers, keep the volumes
#   setup stop               stop containers, keep them
#   setup restart [service]  restart everything, or one service
#   setup status             what is running, with health
#   setup logs [service]     follow logs
#   setup test               run the KMIP engine test suite in the container
#   setup shell [service]    a shell inside a container (default: api)
#   setup backup [dir]       copy both volumes to dir
#   setup restore [dir]      restore both volumes      (stack must be down)
#   setup backups [dir]      list what is in the backup folder
#   setup destroy            remove containers AND volumes - deletes all keys
#   setup help               this text
#
# Safe to re-run: everything it does is idempotent.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$ROOT/cryptohub_lite/docker-compose.yml"
PROJECT="cryptohub-lite"
API_IMAGE="cryptohub-lite/api:dev"
BACKUP_DIR_DEFAULT="${CHL_BACKUP_DIR:-/c/Internal_Idemia/Docker_bkup}"

info()  { printf '\033[0;36m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[0;32m  ok\033[0m %s\n' "$*"; }
warn()  { printf '\033[0;33m  warn\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31merror\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '5,24p' "${BASH_SOURCE[0]}" | sed 's/^#\{1,2\} \{0,1\}//'
    printf '\nWorks with Rancher Desktop or Docker Desktop; the engine is detected at\n'
    printf 'run time. Force one with:  CHL_ENGINE=nerdctl setup ...\n'
}

cmd="${1:-up}"
arg="${2:-}"

case "$cmd" in help|--help|-h) usage; exit 0 ;; esac

# Rancher Desktop and Docker Desktop both work; engine.sh decides which CLI is
# present and reachable and explains what to do when neither is, so no
# subcommand below has to.
# shellcheck source=engine.sh
. "$SCRIPT_DIR/engine.sh"
chl_require_engine

# $COMPOSE is unquoted throughout on purpose: it may be two words.
compose() { $COMPOSE -f "$COMPOSE_FILE" "$@"; }

# ── volumes ──────────────────────────────────────────────────────────────────
# Volumes, not images. Images rebuild from source in minutes; these two cannot
# be rebuilt from anything:
#
#   chl_pgdata  PostgreSQL - user accounts, audit trail, KMIP metadata
#   chl_tokens  the SoftHSM2 token - the actual key material
#
# Saving images instead is what lost the previous environment: `docker save`
# captures images only, so when the engine went away the keys went with it.
#
# The two are one unit. Objects reference key material by CKA_ID and secret
# blobs are encrypted under a master key on the token, so a database restored
# beside a different token is not a degraded backup, it is unreadable. Both are
# therefore always copied and restored together.
VOLUMES="chl_pgdata chl_tokens"

do_backup() {
    local dest="${1:-$BACKUP_DIR_DEFAULT}"
    mkdir -p "$dest"

    # A hot copy of a running PostgreSQL is a torn snapshot, so warn rather
    # than produce an archive that only looks like a backup.
    if "$ENGINE" ps --format '{{.Names}}' 2>/dev/null | grep -qi chl-postgres; then
        warn "chl-postgres is running. A copy taken while it writes may not restore"
        warn "cleanly. For a dependable backup:  setup down  &&  setup backup"
        echo
    fi

    local v
    for v in $VOLUMES; do
        "$ENGINE" volume inspect "${PROJECT}_$v" >/dev/null 2>&1 || fail \
            "Volume ${PROJECT}_$v does not exist. Has the stack ever run?
      Volumes are per-engine: a stack previously run under a different
      engine has its volumes there, not under $ENGINE."
    done

    info "Writing to $dest (via $ENGINE)"
    for v in $VOLUMES; do
        "$ENGINE" run --rm -v "${PROJECT}_$v:/source:ro" -v "$dest:/backup" alpine \
            tar czf "/backup/$v.tgz" -C /source . || fail "Backup of $v failed."
        ok "$v.tgz  $(wc -c < "$dest/$v.tgz") bytes"
    done
    echo
    info "Done. Restore with:  setup restore"
}

do_restore() {
    local dest="${1:-$BACKUP_DIR_DEFAULT}"
    [ -f "$dest/chl_pgdata.tgz" ] || fail "$dest/chl_pgdata.tgz not found."

    # Restoring into a running stack would have PostgreSQL writing to files
    # being replaced underneath it.
    if [ -n "$(compose ps --quiet 2>/dev/null)" ]; then
        fail "The stack is running. Stop it first:  setup down"
    fi

    info "Restoring into ${PROJECT}_chl_pgdata and ${PROJECT}_chl_tokens (via $ENGINE)"
    local v
    for v in $VOLUMES; do
        "$ENGINE" volume create "${PROJECT}_$v" >/dev/null
        "$ENGINE" run --rm -v "${PROJECT}_$v:/target" -v "$dest:/backup" alpine \
            sh -c "rm -rf /target/* /target/..?* 2>/dev/null; tar xzf /backup/$v.tgz -C /target" \
            || fail "Restore of $v failed."
        ok "$v restored"
    done
    info "Done. Bring the stack back up:  setup up"
}

do_up() {
    info "Container engine: $(chl_engine_label)"
    info "Building images (SoftHSM2 is compiled from source; first run takes a few minutes)"
    compose build

    # Retried, because on Rancher Desktop for Windows this step intermittently
    # dies with:
    #
    #     Error response from daemon: failed to connect to the backend:
    #     timed out dialing Hyper-V socket
    #
    # That is the host-to-VM channel Rancher's network tunnel runs over
    # (host-switch <-> vm-switch), not anything about this stack, and it is
    # transient - a second attempt normally succeeds. Recent Rancher versions
    # removed the setting that used to disable the tunnel, so it cannot be
    # configured away.
    #
    # Retrying is safe because `up -d` is idempotent: containers already
    # created are left alone and only the missing ones are started, so a
    # half-finished attempt needs no cleanup first.
    info "Starting the stack"
    local attempt
    for attempt in 1 2 3; do
        if compose up -d; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            printf '\n'
            fail "The stack did not start after $attempt attempts.
      If the message above mentions \"timed out dialing Hyper-V socket\", the
      engine's host-to-VM channel is wedged rather than busy. Cycle it:
          rdctl shutdown && wsl --shutdown     then relaunch Rancher Desktop"
        fi
        warn "attempt $attempt failed; retrying in 5s (see the note in this script)"
        sleep 5
    done

    info "Waiting for the API to report healthy"
    local attempt
    for attempt in $(seq 1 60); do
        if curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then
            ok "API is serving"
            break
        fi
        [ "$attempt" -eq 60 ] && fail "API did not become healthy. Inspect: setup logs api"
        sleep 2
    done

    if curl -fsS http://localhost:8000/api/health | grep -q '"hsm_available":true'; then
        ok "HSM token is available"
    else
        warn "HSM is not available; check: setup logs api"
    fi

    cat <<BANNER

  IDEMIA CryptoHub Lite is running on $ENGINE.

    Portal      http://localhost:8081       admin / admin123
    REST API    http://localhost:8000/api/docs
    KMIP        localhost:5696
    PostgreSQL  not published; reachable only inside the stack

  Change the bootstrap administrator password before doing anything else:
  click your name in the top-right -> My Account.
  Back up before you rely on it:  setup backup

BANNER
}

case "$cmd" in
    up)      do_up ;;
    down)    compose down ;;
    stop)    compose stop ;;
    restart) compose restart ${arg:+"$arg"} ;;
    status|ps) compose ps ;;
    logs)    compose logs -f --tail 100 ${arg:+"$arg"} ;;
    # A one-off container over the *source tree*, not `exec` into the running
    # api service, and not the copy of the package baked into the image.
    #
    # Two reasons, both learned by getting 8 failures the other way. Six tests
    # read deployment artifacts - deploy/config.example.yaml, the systemd unit,
    # the CI workflow - and Dockerfile.api copies none of those into the
    # runtime image, so they can never pass inside it. And testing the baked
    # copy tests the last build rather than the working tree, which is rarely
    # what is wanted while editing. Mounting the repo fixes both, and matches
    # what CI runs.
    #
    # pytest is deliberately absent from the runtime image - it is a test
    # dependency - so it is installed into the throwaway container each time.
    test)
        info "Running the KMIP engine test suite (via $ENGINE)"
        "$ENGINE" run --rm --entrypoint sh -e PYTHONPATH=/src \
            -v "$ROOT:/src" -w /src "$API_IMAGE" \
            -c "python -c 'import pytest' 2>/dev/null || pip install --quiet pytest; python -m pytest kmip_pkcs11/tests -q"
        ;;
    shell)   compose exec "${arg:-api}" sh ;;
    backup)  do_backup "$arg" ;;
    restore) do_restore "$arg" ;;
    backups)
        dest="${arg:-$BACKUP_DIR_DEFAULT}"
        info "Backups in $dest"
        ls -1t "$dest"/chl_*.tgz 2>/dev/null || echo "  (none)"
        ;;
    destroy)
        echo "This removes the containers AND both volumes."
        echo "Every key on the token and every account, audit row and KMIP object is"
        echo "deleted, and none of it can be rebuilt from source."
        echo
        read -r -p "Type DESTROY to confirm: " confirm
        [ "$confirm" = "DESTROY" ] || fail "Cancelled. Nothing was removed."
        compose down -v
        ;;
    *)
        printf '\033[0;31merror\033[0m Unknown command %s\n\n' "$cmd" >&2
        usage >&2
        exit 1
        ;;
esac
