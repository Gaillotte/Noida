#!/usr/bin/env bash
#
# Container engine detection, shared by every script that needs one.
#
# The stack runs unchanged on Rancher Desktop and Docker Desktop — the images
# are plain OCI and the compose file uses nothing vendor-specific. What differs
# is only which CLI is on PATH, so this resolves that once instead of each
# script assuming `docker`.
#
# Source it, then use "$ENGINE" and $COMPOSE:
#
#     . "$(dirname "$0")/engine.sh"
#     chl_require_engine
#     $COMPOSE -f "$COMPOSE_FILE" up -d
#
# $COMPOSE is deliberately unquoted at the call site: it can be two words
# ("docker compose"), and quoting it would look for a binary with a space in
# its name.
#
# Override the choice with CHL_ENGINE=docker or CHL_ENGINE=nerdctl when both
# are present and you want a specific one.

# Populated by chl_detect_engine.
ENGINE=""
COMPOSE=""
CHL_ENGINE_DETAIL=""

# Probed in this order. `docker` comes first because it covers both Docker
# Desktop and Rancher Desktop's default `moby` engine, which is the
# recommended Rancher setting; `nerdctl` is the fallback for Rancher running
# `containerd`, where a `docker` shim exists but cannot reach a daemon.
_CHL_CANDIDATES="docker nerdctl"

chl_detect_engine() {
    local candidates="${CHL_ENGINE:-$_CHL_CANDIDATES}"
    local found_but_down=""
    local candidate

    for candidate in $candidates; do
        command -v "$candidate" >/dev/null 2>&1 || continue

        # Installed is not the same as running. This is the case that actually
        # bites — the CLI answers, every command fails with a socket error.
        if ! "$candidate" info >/dev/null 2>&1; then
            found_but_down="${found_but_down}${found_but_down:+, }$candidate"
            continue
        fi

        ENGINE="$candidate"

        if "$candidate" compose version >/dev/null 2>&1; then
            COMPOSE="$candidate compose"
        elif [ "$candidate" = "docker" ] && command -v docker-compose >/dev/null 2>&1; then
            # Compose v1, the standalone Python script. Still works here.
            COMPOSE="docker-compose"
        else
            CHL_ENGINE_DETAIL="$candidate is running but has no compose support"
            return 2
        fi
        return 0
    done

    if [ -n "$found_but_down" ]; then
        CHL_ENGINE_DETAIL="$found_but_down"
        return 3
    fi
    return 1
}

# Revive a wedged Rancher Desktop engine. Mirrors heal.cmd; see that file for
# the full account of the fault. Summary: Rancher on Windows intermittently
# loses the Hyper-V socket between the host and the WSL VM, and only cycling
# the distribution clears it.
#
# Refuses while containers are running. Healing a *partial* wedge - engine
# reachable enough to answer some calls, stack still up - tore the VM down
# under a live PostgreSQL and SoftHSM2 token, and the stack came back against
# different storage with an empty database. Stopping containers is advertised;
# silently changing which volumes the engine presents is not.
chl_heal_engine() {
    [ "${CHL_NO_AUTOHEAL:-}" = "1" ] && {
        printf '        Automatic recovery is disabled (CHL_NO_AUTOHEAL=1).\n' >&2
        return 1
    }
    command -v rdctl >/dev/null 2>&1 || {
        printf '        No rdctl on PATH, so this is not Rancher Desktop.\n' >&2
        return 1
    }

    # Three outcomes, not two: `ps` can succeed and list nothing, succeed and
    # list containers, or fail. On a partial wedge it fails, and treating that
    # as "nothing is running" would cycle WSL under a live stack - the accident
    # this guard exists to prevent. The empty case is trusted only when the
    # command actually succeeded; unknown fails closed.
    local engine running="" decided="" out
    for engine in docker nerdctl; do
        command -v "$engine" >/dev/null 2>&1 || continue
        if out="$("$engine" ps -q 2>/dev/null)"; then
            decided="$engine"
            [ -n "$out" ] && running=yes
            break
        fi
    done
    if [ -z "$decided" ] && [ "${CHL_FORCE_HEAL:-}" != "1" ]; then
        printf '\n\033[0;31merror\033[0m Could not determine whether containers are running -\n' >&2
        printf '      the engine answers but its daemon calls fail, which is the partial\n' >&2
        printf '      wedge this guard exists for. Cycling WSL now could tear the VM down\n' >&2
        printf '      underneath a live PostgreSQL and SoftHSM2 token.\n' >&2
        printf '      Force with CHL_FORCE_HEAL=1 only if nothing is running.\n' >&2
        return 1
    fi
    if [ -n "$running" ] && [ "${CHL_FORCE_HEAL:-}" != "1" ]; then
        printf '\n\033[0;31merror\033[0m The engine still lists running containers, so this is a\n' >&2
        printf '      partial wedge. Cycling WSL now would tear the VM down underneath\n' >&2
        printf '      them, which has previously lost the database and token.\n' >&2
        printf '      Back up and stop first:  setup backup  &&  setup down\n' >&2
        printf '      Or force it with CHL_FORCE_HEAL=1 if the volumes are expendable.\n' >&2
        return 1
    fi

    printf '\033[0;36m==>\033[0m Reviving the container engine (Rancher Desktop)\n'
    printf '    [1/4] rdctl shutdown\n';  rdctl shutdown >/dev/null 2>&1 || true

    # `wsl --shutdown` stops every distribution, not just Rancher's.
    local foreign
    foreign="$(wsl.exe -l -q 2>/dev/null | tr -d '\r\000' | grep -v '^$' \
               | grep -iv '^rancher-desktop' | head -1)"
    if [ -n "$foreign" ]; then
        printf "    [2/4] skipping 'wsl --shutdown': %s is also registered\n" "$foreign"
    else
        printf '    [2/4] wsl --shutdown\n'; wsl.exe --shutdown >/dev/null 2>&1 || true
    fi
    sleep 6

    printf '    [3/4] relaunching Rancher Desktop\n'
    local rd="$LOCALAPPDATA/Programs/Rancher Desktop/Rancher Desktop.exe"
    [ -f "$rd" ] || rd="$PROGRAMFILES/Rancher Desktop/Rancher Desktop.exe"
    [ -f "$rd" ] || { printf '          not found; start it yourself.\n' >&2; return 1; }
    ( "$rd" >/dev/null 2>&1 & )

    printf '    [4/4] waiting for the engine (up to 3 minutes)\n'
    local waited=0
    while [ "$waited" -lt 180 ]; do
        sleep 10; waited=$((waited + 10))
        if docker info >/dev/null 2>&1 || nerdctl info >/dev/null 2>&1; then
            printf '\033[0;32m  ok\033[0m engine is up after %ss\n' "$waited"
            return 0
        fi
        printf '          ...%ss\n' "$waited"
    done
    printf '\033[0;31merror\033[0m The engine did not come back after %ss.\n' "$waited" >&2
    return 1
}

# Detect, or explain what to do and exit. Every message names Rancher Desktop
# first: it is what this project is developed against.
chl_require_engine() {
    chl_detect_engine
    local rc=$?
    # Installed but unreachable is repairable, so try once before giving up.
    if [ "$rc" = "3" ] && [ "${CHL_HEALED:-}" != "1" ]; then
        printf '\033[0;33m  warn\033[0m Found %s, but it is not running.\n' "$CHL_ENGINE_DETAIL"
        if chl_heal_engine; then
            CHL_HEALED=1
            chl_detect_engine
            rc=$?
        fi
    fi
    case "$rc" in
        0) return 0 ;;
        2)
            printf '\033[0;31merror\033[0m %s.\n' "$CHL_ENGINE_DETAIL" >&2
            printf '      Install the compose plugin, or use Rancher Desktop, which bundles it.\n' >&2
            exit 1
            ;;
        3)
            printf '\033[0;31merror\033[0m Found %s, but it is not running.\n' "$CHL_ENGINE_DETAIL" >&2
            printf '      Start Rancher Desktop (or Docker Desktop) and wait for it to report ready.\n' >&2
            printf '      If Rancher is open but the engine is wedged:\n' >&2
            printf '          rdctl shutdown && wsl --shutdown     then relaunch\n' >&2
            exit 1
            ;;
        *)
            printf '\033[0;31merror\033[0m No container engine found on PATH.\n' >&2
            printf '      Install Rancher Desktop (recommended) or Docker Desktop.\n' >&2
            printf '      Rancher Desktop: set Container Engine to "moby (dockerd)" in\n' >&2
            printf '      Preferences; "containerd" also works and is used via nerdctl.\n' >&2
            exit 1
            ;;
    esac
}

# A short description for the banner, so it is obvious which engine ran.
chl_engine_label() {
    printf '%s (compose: %s)' "$ENGINE" "$COMPOSE"
}
