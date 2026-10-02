#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/.tools"
archive="$root/.tools/ghidra.zip"
if [[ ! -f "$archive" ]]; then
    curl -fL --retry 3 \
        https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip \
        -o "$archive.part"
    mv "$archive.part" "$archive"
fi
echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  $archive" | sha256sum -c -
if [[ ! -d "$root/.tools/ghidra_12.1.4_PUBLIC" ]]; then
    unzip -q "$archive" -d "$root/.tools"
fi
