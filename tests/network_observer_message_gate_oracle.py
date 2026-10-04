#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    observer=h.table;connections=observer+0x2000;storage=observer+0x3000;rng=random.Random(0x768b0)
    query=h.lib.h2_network_observer_message_deferred;mark=h.lib.h2_network_observer_defer_message
    for f in [query,mark]:f.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3
    query.restype=C.c_uint8;mark.restype=None
    types=[0,1,25,31,32,33,63,64,65,127,128,255,256,257,287,288,319,320,0xffffffff,0x80000000]
    coverage=dict(absent=0,inactive=0,unmarked=0,marked=0,wide_shift=0,negative=0,allowed=0,deferred=0)
    for case in range(2048):
        index=case%3;entry=observer+0xa8+index*0x528;id=[0,1,0xffffffff][case//3%3];conn=connections+(id if id!=0xffffffff else 0)*0xf8;state=[2,3,4,5,5,5,8,0xffffffff][case//9%8];kind=types[case%len(types)]
        h.write(observer,rng.randbytes(0x1100));h.write(connections,rng.randbytes(0x200));h.write(storage,rng.randbytes(0x40));h.write(0x4d87d4,P(connections));h.write(0x4d87dc,P(storage));h.write(entry+12,P(id));h.write(conn+0x54,P(state));h.write(conn+0x48,P(16 if case%4 else 0));h.write(conn+0x14,P(0))
        low=rng.getrandbits(32);high=rng.getrandbits(32)
        if case%3==0:low=high=0
        elif case%3==1:low=high=0xffffffff
        h.write(entry+0x520,P(low)+P(high))
        old=rng.getrandbits(32);delta=[-512,-385,-384,-383,-129,-128,-127,0,127,0x1000000,0x7fffffff,rng.getrandbits(32)][case//7%12];h.write(storage+0x18,P(old)+P(old+delta))
        value=h.call('message_deferred',0x768b0,dict(ecx=observer,eax=index),[kind],lambda:query(h.memory,observer,index,kind),255)
        result=query(h.memory,observer,index,kind);coverage['deferred' if result else 'allowed']+=1
        coverage['absent']+=id==0xffffffff;coverage['inactive']+=state!=5
        shift=kind&255;mask=(1<<shift) if shift<64 else 0;coverage['wide_shift']+=shift>=64;coverage['marked' if ((high<<32)|low)&mask else 'unmarked']+=1
        coverage['negative']+=bool(((delta+512)*128&0xffffffff)&0x80000000)
        h.call('defer_message',0x76930,dict(ecx=observer,eax=index),[kind],lambda:mark(h.memory,observer,index,kind))
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-message-gate-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_observer_message_gate.c','include/halo2/network_observer_message_gate.h','src/network_observer_retry.c','tests/network_observer_message_gate_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original message deferral query/mark, actual connection send-capacity and CRT64-bit shift instructions; no hooks. Full persistent memory, AL and stack purge. Missing/inactive/connected entries, existing/new flags, both capacity thresholds, signed/wrapped capacity, low-byte shift semantics and zero masks. No session-state snapshot generation or live network.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
