#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    f=h.lib.h2_network_session_reset_snapshots;f.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint8];f.restype=None
    rng=random.Random(0x60fa0);counts=[0,1,2,8,15,16,0xffffffff,0x80000000]
    flags=[0,1,128,255,256,257,0xffffff00,0xffffffff]
    for case in range(1024):
        session=h.table+case%4;count=counts[case%8];flag=flags[case//8%8]
        h.write(session,rng.randbytes(0x7900));h.write(session+0x54,P(count))
        h.write(session+0x4978,P([0,1,0xffffffff,0x7fffffff,rng.getrandbits(32)][case%5]))
        h.call('reset_snapshots',0x60fa0,dict(edx=session),[flag],lambda:f(h.memory,session,flag&255))
    return dict(cases=1024,negative_counts=256,unaligned=True,low_byte_flags=True,generation_wrap=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-snapshot-reset-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_session_snapshot_reset.c','include/halo2/network_session_snapshot_reset.h','tests/network_session_snapshot_reset_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original snapshot reset, no hooks. Full persistent memory and stack purge. Signed empty/negative/valid peer counts, raw stack flags with low-byte semantics, randomized adjacent data, unaligned sessions, generation wrap. No host transition or live migration.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
