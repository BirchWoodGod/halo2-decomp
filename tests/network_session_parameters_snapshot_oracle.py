#!/usr/bin/env python3
"""Parameter delta constructor, with original CRT string callees intact."""
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x609e0);session=h.table;current=session+0x8000;baseline=session+0xa000;output=session+0xc000
    fn=h.lib.h2_network_session_build_parameters_snapshot;fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4;fn.restype=None
    flags=[0x10,0x1c,0x24,0x2c,0x38,0x42,0x48,0x4a,0x50,0x70,0x52,0x88,0x78,0x394,0x420,0x430,0x438,0x440,0x574,0x5b6,0x1464,0x1466,0x146a,0x1484,0x14cc]
    coverage={hex(f):[0,0] for f in flags}
    edges=[0,4,8,0x10,0x14,0x18,0x1c,0x20,0x21,0x28,0x29,0x2c,0x30,0x34,0x40,0x4b,0x4c,0x50,0x54,0x58,0x6c,0x70,0x78,0x80,0x84,0x85,0x88,0x38f,0x390,0x394,0x398,0x417,0x428,0x42f,0x430,0x434,0x438,0x567,0x568,0x5a6,0x5a8,0x5ac,0x617,0x618,0x1457,0x1458,0x1460,0x1464,0x14a7,0x14a8]
    for case in range(2048):
        h.write(session,rng.randbytes(0x7900));data=bytearray(rng.randbytes(0x14ac))
        data[0x54:0x58]=struct.pack('<I',[0,1,2,3,4,0xffffffff][case%6])
        # Nulls at the start/end/interior and unterminated fields, including nonzero tails.
        pos=[None,0,1,63,126,127][case//6%6]
        if pos is not None:data[0x398+pos]=0
        pos=[None,0,1,15,30,31][case//36%6]
        if pos is not None:data[0x568+pos*2:0x56a+pos*2]=bytes(2)
        other=bytearray(data)
        if case%4==1:
            off=edges[case//4%len(edges)];other[off]^=0xff
        elif case%4==2:
            for _ in range(12):other[rng.randrange(len(other))]^=rng.randrange(1,256)
        h.write(current,bytes(data));h.write(baseline,bytes(other));h.write(output,rng.randbytes(0x14d8))
        b=0 if case%4==0 else (current if case%4==3 else baseline)
        h.call('session_build_parameters_snapshot',0x609e0,dict(eax=session,ebx=current),[b,output],lambda:fn(h.memory,session,current,b,output),None)
        for f in flags:coverage[hex(f)][bool(h.read(output+f,1)[0])]+=1
    assert all(no and yes for no,yes in coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_session_parameters_snapshot_preview.so');p.add_argument('--report',default='analysis/network-session-parameters-snapshot-preview.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    sources=['src/network_session_parameters_snapshot.c','include/halo2/network_session_parameters_snapshot.h','tests/network_session_parameters_snapshot_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,total_comparisons=sum(h.counts.values()),field_flag_coverage=coverage,source_hashes={s:sha(ROOT/s) for s in sources},scope='Original constructor and CRT callees intact; full guest memory/stack purge. Null/equal/current-aliased baselines, single-field and sparse changes, all 25 flags both ways, tagged union variants, narrow and UTF16 null/truncation/nonzero-tail cases. Output disjoint from inputs. Not live snapshot broadcast.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
