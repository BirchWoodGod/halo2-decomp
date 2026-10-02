#!/usr/bin/env bash
# Experimental Linux frontend for the retained Xita translated runtime.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export H2_HOST_BIN=${H2_HOST_BIN:-"$root/build/xita-linux/harness"}
export H2_DRIVE=${H2_DRIVE:-0}
export H2_DRIVER="$root/scripts/xita-menu-driver.py"
[[ -x "$H2_HOST_BIN" ]] || { echo 'Run python3 scripts/build-xita-linux.py first.' >&2; exit 2; }
exec bash "$root/scripts/run-xita-reference.sh" "${1:-3600}" "${2:-linux-$(date -u +%Y%m%dT%H%M%SZ)-$$}" XV_MENU_GXM=0 "${@:3}"
