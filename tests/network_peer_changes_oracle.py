#!/usr/bin/env python3
"""Peer change constructor: original string routines execute without hooks."""
import argparse,ctypes as C,hashlib,json,random
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x602b0);current=h.table;baseline=current+0x200;output=current+0x400
    fn=h.lib.h2_network_peer_changes;fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;fn.restype=None
    coverage={hex(k):[0,0] for k in [0,0x62,0x6c,0x8c,0xd0]}
    for case in range(2048):
        data=bytearray(rng.randbytes(0xc8))
        for off,n in [(0,16),(32,32)]:
            pos=[None,0,1,n-2,n-1][case//8%5]
            if pos is not None:data[off+pos*2:off+pos*2+2]=bytes(2)
        other=bytearray(data)
        if case%4==1:other[case//4%0xc8]^=0xff
        elif case%4==2:
            for _ in range(10):other[rng.randrange(0xc8)]^=rng.randrange(1,256)
        h.write(current,bytes(data));h.write(baseline,bytes(other));seed=rng.randbytes(0xd8)
        if case%2:seed=bytes(0xd8)
        h.write(output,seed);b=0 if case%4==0 else current if case%4==3 else baseline
        h.call('peer_changes',0x602b0,dict(ebx=output),[current,b],lambda:fn(h.memory,current,b,output),None)
        if case%2:
            for key in coverage:coverage[key][bool(h.read(output+int(key,16),1)[0])]+=1
    assert all(no and yes for no,yes in coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-peer-changes-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources=['src/network_peer_changes.c','include/halo2/network_peer_changes.h','tests/network_peer_changes_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,total_comparisons=sum(h.counts.values()),flag_coverage=coverage,source_hashes={s:sha(ROOT/s) for s in sources},scope='Full memory and ret8, original CRT strings intact. Null/equal/current-aliased baseline, single-byte/sparse differences, UTF16 null/truncation/nonzero tails; seeded and zero outputs. Disjoint output only; no membership broadcast integration.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
