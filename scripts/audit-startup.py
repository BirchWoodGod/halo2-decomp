#!/usr/bin/env python3
"""Inventory direct lifecycle entrypoints; never equate this with boot coverage."""
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    catalogs=[json.loads((ROOT/'config'/p).read_text()) for p in ['data_array_abi.json','host_bridge_abi.json']]
    data=(ROOT/'default.xbe').read_bytes();digest=hashlib.sha256(data).hexdigest()
    assert all(c['xbe_sha256']==digest for c in catalogs)
    known={int(f['address'],16):f for c in catalogs for f in c['functions']}
    info=json.loads((ROOT/'analysis/xbe.json').read_text())
    def read32(address):
        for s in info['sections']:
            if s['virtual_address']<=address and address+4<=s['virtual_address']+s['raw_size']:
                return struct.unpack_from('<I',data,s['raw_address']+address-s['virtual_address'])[0]
        raise ValueError(hex(address))
    phases=[]
    for column,name in enumerate(['initialize','dispose','initialize_for_map','dispose_from_map','initialize_for_structure','dispose_from_structure']):
        rows=[]
        for i in (range(67,-1,-1) if column in [1,3,5] else range(68)):
            target=read32(0x440dd8+i*36+column*4)
            if target:
                f=known.get(target)
                rows.append(dict(index=i,address=f'{target:08x}',native_name=f['name'] if f else None))
        phases.append(dict(phase=name,nonzero_entries=len(rows),catalogued_entries=sum(r['native_name'] is not None for r in rows),shared_noop_entries=sum(r['native_name']=='h2_lifecycle_noop' for r in rows),unique_catalogued_targets=len({r['address'] for r in rows if r['native_name'] is not None}),entries=rows))
    report=dict(xbe_sha256=digest,scope='Direct entrypoint inventory only. Catalogued routines may still require unrecovered dependencies/platform services. Not execution or transitive boot coverage.',phases=phases)
    (ROOT/'analysis/startup-coverage.json').write_text(json.dumps(report,indent=2)+'\n')
    for phase in phases:
        missing=[r['address'] for r in phase['entries'] if r['native_name'] is None]
        print(f"{phase['phase']}: {phase['catalogued_entries']}/{phase['nonzero_entries']} direct entries catalogued ({phase['shared_noop_entries']} shared no-op slots); first missing: {missing[0] if missing else 'none'}")
if __name__=='__main__':main()
