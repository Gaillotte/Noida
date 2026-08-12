#!/usr/bin/env bash
# Convenience launcher for the script under cryptohub_lite/scripts/.
exec "$(dirname "${BASH_SOURCE[0]}")/cryptohub_lite/scripts/setup.sh" "$@"
