#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ghidra_dir=${GHIDRA_HOME:-"$root/.tools/ghidra_12.1.4_PUBLIC"}
python3 "$root/scripts/prepare.py"
mkdir -p "$root/analysis/ghidra"
if [[ ${1:-} == --recover ]]; then
    "$ghidra_dir/support/analyzeHeadless" "$root/analysis/ghidra" Halo2 \
        -process default.xbe -scriptPath "$root/scripts/ghidra" \
        -preScript DiscoverEngine.java "$root" \
        -preScript RecoverSwitches.java "$root" \
        -postScript VerifyMapping.java "$root" -postScript AnnotateDataArray.java "$root" \
        -postScript ExportHalo2.java "$root" -postScript IndexEngine.java "$root" \
        -analysisTimeoutPerFile 600 -max-cpu 4
elif [[ ${1:-} == --resume ]]; then
    "$ghidra_dir/support/analyzeHeadless" "$root/analysis/ghidra" Halo2 \
        -process default.xbe -noanalysis -scriptPath "$root/scripts/ghidra" \
        -postScript VerifyMapping.java "$root" -postScript AnnotateDataArray.java "$root" \
        -postScript ExportHalo2.java "$root" \
        -postScript IndexEngine.java "$root" -max-cpu 4
else
    if [[ -e "$root/analysis/ghidra/Halo2.gpr" ]]; then
        echo 'Project already exists; use --resume to export or open the project in Ghidra.' >&2
        exit 1
    fi
    "$ghidra_dir/support/analyzeHeadless" "$root/analysis/ghidra" Halo2 \
        -import "$root/default.xbe" -loader BinaryLoader -processor x86:LE:32:default -cspec windows \
        -scriptPath "$root/scripts/ghidra" -preScript LoadHalo2.java "$root" \
        -preScript DiscoverEngine.java "$root" \
        -preScript RecoverSwitches.java "$root" \
        -postScript VerifyMapping.java "$root" -postScript AnnotateDataArray.java "$root" \
        -postScript ExportHalo2.java "$root" \
        -postScript IndexEngine.java "$root" -analysisTimeoutPerFile 600 -max-cpu 4
fi
python3 - "$root" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1]) / 'analysis'
assert json.loads((out / 'mapping-verification.json').read_text())['passed']
summary = json.loads((out / 'export-summary.json').read_text())
assert summary['decompiled'] > 0 and not summary['cancelled'], summary
catalog = json.loads((out.parent / 'config/data_array_abi.json').read_text())
bridge = json.loads((out.parent / 'config/host_bridge_abi.json').read_text())
assert json.loads((out / 'abi-annotations.json').read_text())['annotated'] == len(catalog['functions']) + len(bridge['functions'])
assert (out / 'engine-candidates.tsv').is_file()
print(summary)
PY
