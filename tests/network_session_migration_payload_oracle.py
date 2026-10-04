#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    f=h.lib.h2_network_session_build_migration_payload
    f.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];f.restype=C.c_uint32
    rng=random.Random(0x62b70);session=h.table
    for case in range(768):
        h.write(session,rng.randbytes(0x9000))
        host=case%16;local=case//16%16
        h.write(session+0x40,P(host));h.write(session+0x72d8,P(local))
        # Separate, unaligned, and overlapping identity outputs. Control indexes
        # stay valid even when the original zero/copy loop overwrites identity.
        out=[session+0x8000,session+0x8001,session+0x58+host*0x10c,
             session+0x5c+local*0x10c,session+0x54+local*0x10c,
             session+0x7300][case%6]
        h.call('migration_payload',0x62b70,dict(edx=session,ebx=out),[],lambda:f(h.memory,session,out),0xffffffff)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-migration-payload-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    files=['src/network_session_migration_payload.c','include/halo2/network_session_migration_payload.h','tests/network_session_migration_payload_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,source_hashes={f:H(ROOT/f) for f in files},scope='Original migration payload builder without hooks; full persistent memory, EAX and stack purge. All 16 host/local indexes, same/different peers, randomized identities, unaligned and overlapping output. No migration state transition or live networking.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
