#!/usr/bin/env bash
# Reproduce the retained Xita Halo 2 Linux baseline with isolated saves.
# This runs Xita's headless translated game, not libhalo2_engine.so.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
xita_stage=${XITA_REFERENCE_ROOT:-/home/birchwoodgod/xita-backups/2026-09-24-halo2-vita3k}
seconds=${1:-120}
tag=${2:-decomp-$(date -u +%Y%m%dT%H%M%SZ)-$$}
[[ "$seconds" =~ ^[1-9][0-9]*$ ]] || { echo 'Seconds must be a positive integer.' >&2; exit 2; }
[[ "$tag" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'Tag may contain letters, digits, underscores and hyphens.' >&2; exit 2; }
export H2_HOST_BASE="$root/analysis/xita-host"
export H2_HOST_APP0="$xita_stage/private/hostrun/app0-h2v1r"
export H2_HOST_SAVE_FROM="$xita_stage/private/hostrun/save-base"
export H2_HOST_BIN=${H2_HOST_BIN:-"$xita_stage/private/objs-x86-h2v1r/harness"}
export H2_HOST_BARE=1
export H2_DRIVE=${H2_DRIVE:-1}
for path in "$H2_HOST_APP0" "$H2_HOST_SAVE_FROM" "$H2_HOST_BIN" "$xita_stage/source/tools/h2_host_run.sh"; do
    [[ -e "$path" ]] || { echo "Missing Xita reference artifact: $path" >&2; exit 2; }
done
exec sh "$xita_stage/source/tools/h2_host_run.sh" "$tag" "$seconds" "${@:3}"
