#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    f=h.lib.h2_network_peer_mask_count;f.argtypes=[C.c_uint32];f.restype=C.c_uint32
    rng=random.Random(0x63ca0)
    masks=[0,0xffffffff,0x55555555,0xaaaaaaaa]+[1<<i for i in range(32)]+[0xffffffff^(1<<i) for i in range(32)]+[rng.getrandbits(32) for _ in range(956)]
    for mask in masks:
        h.call('peer_mask_count',0x63ca0,dict(ecx=mask),[],lambda:f(mask),0xffffffff)
        assert f(mask)==mask.bit_count()
    return dict(cases=len(masks),all_single_bits=True,all_single_clear_bits=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-peer-mask-count-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_peer_mask_count.c','include/halo2/network_peer_mask_count.h','tests/network_peer_mask_count_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original population count instructions, no hooks. Full persistent memory, EAX and stack purge. Empty/full/alternating masks, every single set/clear bit and random masks; independent Python bit_count check. Dependency of handoff ranking, not complete ranking.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
