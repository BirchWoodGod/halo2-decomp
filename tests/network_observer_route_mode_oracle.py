#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x7a4a0);o=h.table;counts={'mode0':0,'mode1':0,'mode2':0,'unchanged':0}
    fn=h.lib.h2_network_observer_update_route_mode;fn.argtypes=[C.POINTER(Memory),C.c_uint32];fn.restype=None
    for case in range(1536):
        h.write(o,rng.randbytes(0x4e00))
        for i in range(15):
            e=o+0xa8+i*0x528;h.write(e,struct.pack('<I',1 if (case+i)%4 else 0));h.write(e+0x48c,bytes([1 if (case+i)%5 else 0]))
            for j,off in enumerate([0x4c0,0x48e,0x48f,0x50c,0x50e]):h.write(e+off,bytes([rng.choice([1,2,128,255]) if (case&(1<<j)) and i==case%15 else 0]))
        h.write(0x4cf73c,bytes([case//32%2]));h.write(0x4c99b8,bytes([case%7!=0]));h.write(0x4c987c,struct.pack('<I',0xdeadbeef))
        h.call('route_mode',0x7a4a0,dict(eax=o),[],lambda:fn(h.memory,o))
        value=h.u32(0x4c987c);counts['unchanged' if value==0xdeadbeef else 'mode'+str(value)]+=1
    assert all(counts.values()),counts
    return counts

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-route-mode-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_observer_route_mode.c','include/halo2/network_observer_route_mode.h','tests/network_observer_route_mode_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original fifteen-slot route-mode aggregation; full persistent memory. Active/enabled filtering, each slot, noncanonical nonzero flag bytes, all three modes and disabled global store. No whole observer frame or game execution.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
