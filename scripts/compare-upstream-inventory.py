#!/usr/bin/env python3
"""Compare an upstream function inventory with our reviewed ABI catalogs.

No upstream status is promoted to local validation. No game bytes are read.
The report omits the upstream atlas-derived name and object columns.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_XBE = "03215919bb7163259257d361f4c7bf802a7ab12aa85e2689436369b5c427935d"


def compare(inventory, catalogs, upstream_commit):
    if len(upstream_commit) != 40 or any(c not in "0123456789abcdef" for c in upstream_commit):
        raise ValueError("upstream commit must be a full lowercase Git SHA")
    local = {}
    for path in catalogs:
        catalog = json.loads(path.read_text())
        if catalog["xbe_sha256"] != EXPECTED_XBE:
            raise ValueError(f"different XBE in {path}")
        for function in catalog["functions"]:
            address = int(function["address"], 16)
            if address in local:
                raise ValueError(f"duplicate local address {address:08x}")
            local[address] = function
    upstream = {}
    with inventory.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        required = {"va", "size", "owner", "source", "status", "calls"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("upstream inventory lacks required columns")
        for row in reader:
            address = int(row["va"], 16)
            if address in upstream:
                raise ValueError(f"duplicate upstream address {address:08x}")
            upstream[address] = row

    def entry(address):
        row = upstream[address]
        result = dict(address=f"{address:08x}", upstream_status=row["status"],
                      upstream_source=row["source"], upstream_owner=row["owner"],
                      upstream_size=int(row["size"]))
        if address in local:
            result.update(local_name=local[address]["name"],
                          local_source=local[address].get("source"))
        return result

    matched = {a for a, r in upstream.items() if r["status"] == "matched"}
    shared = sorted(matched & local.keys())
    candidates = []
    for address in sorted(matched - local.keys()):
        row = upstream[address]
        if row["owner"] != "game":
            continue
        calls = {int(value, 16) for value in row["calls"].split()}
        item = entry(address)
        item["callees_outside_local_catalog"] = [f"{a:08x}" for a in sorted(calls - local.keys())]
        candidates.append(item)
    candidates.sort(key=lambda r: (len(r["callees_outside_local_catalog"]), r["upstream_size"], r["address"]))
    return dict(
        upstream_repository="https://github.com/kirklandsig/halo2-decompiled",
        upstream_commit=upstream_commit,
        target_xbe_sha256=EXPECTED_XBE,
        input_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in [inventory, *catalogs]},
        scope="Address cross-reference only. Upstream match claims have not been reproduced. "
              "Catalog membership is not whole-game validation; call lists omit indirect dependencies. "
              "Caller must supply an inventory for the pinned target XBE.",
        local_routines=len(local), upstream_rows=len(upstream),
        upstream_reported_matches=len(matched),
        shared_reported_matches=[entry(a) for a in shared],
        upstream_game_candidates=candidates,
        local_without_upstream_match=[entry(a) for a in sorted(local.keys() & upstream.keys() - matched)],
        local_missing_from_upstream=[f"{a:08x}" for a in sorted(local.keys() - upstream.keys())],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = compare(args.inventory, [ROOT / "config/data_array_abi.json",
                                     ROOT / "config/host_bridge_abi.json"], args.upstream_commit)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"local_routines": report["local_routines"],
                      "upstream_reported_matches": report["upstream_reported_matches"],
                      "shared_reported_matches": len(report["shared_reported_matches"]),
                      "upstream_game_candidates": len(report["upstream_game_candidates"]),
                      "local_missing_from_upstream": len(report["local_missing_from_upstream"])}))


if __name__ == "__main__":
    main()
