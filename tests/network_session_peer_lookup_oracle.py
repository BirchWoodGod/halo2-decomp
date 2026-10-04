#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    f=h.lib.h2_network_session_find_peer_identity;f.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];f.restype=C.c_uint32
    rng=random.Random(0x63ba0);counts=[0,1,2,3,8,16,31,32,0xffffffff,0x80000000]
    coverage={'no_match':0,'single':0,'duplicate':0,'negative':0,'alias':0}
    for case in range(1024):
        table=h.table+case%4;identity=table+0x400+case%3;count=counts[case%len(counts)];n=count if count<100 else 0
        h.write(table,rng.randbytes(0x500));h.write(table+0x54,P(count));key=rng.randbytes(6);h.write(identity+10,key)
        if n and case%4:
            h.write(table+0x58+(case%n)*6,key)
            if case%4==2:h.write(table+0x58+(n-1)*6,key)
        if n and case%7==0:identity=table+0x58+(case%n)*6-10;key=h.read(identity+10,6);coverage['alias']+=1
        matches=[i for i in range(n) if h.read(table+0x58+i*6,6)==key]
        coverage['no_match' if not matches else 'single' if len(matches)==1 else 'duplicate']+=1;coverage['negative']+=count>=0x80000000
        h.call('find_peer_identity',0x63ba0,dict(ecx=table,edx=identity),[],lambda:f(h.memory,table,identity),0xffffffff)
        assert f(h.memory,table,identity)==(matches[-1] if matches else 0xffffffff)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-peer-lookup-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_session_peer_lookup.c','include/halo2/network_session_peer_lookup.h','tests/network_session_peer_lookup_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original six-byte identity lookup, no hooks. Full persistent memory, EAX, stack purge; empty/negative/bounded positive counts, absent/unique/duplicate identities, last match, unaligned and aliased input. No migration update or live networking.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
