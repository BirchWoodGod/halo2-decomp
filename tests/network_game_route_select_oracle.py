#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x56790);base=h.table;coverage={'selected':0,'deferred':0,'aliases':0}
    sites={0x5680c:'selected',0x56881:'selected',0x568f5:'selected',0x56966:'selected',0x567f4:'deferred',0x56869:'deferred',0x568dc:'deferred',0x56952:'deferred'}
    def hook(u,at,size,ctx):coverage[sites[at]]+=1
    for at in sites:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_game_select_routes;fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4+[C.c_uint8]+[C.c_uint32]*2;fn.restype=None
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    for case in range(2048):
        h.write(base,rng.randbytes(64));remaining=base;pending=base+8;selected=base+16;deferred=base+24
        if case%3==0:
            selected=[remaining,pending,pending+1,remaining+2][case//3%4];deferred=[remaining,pending,selected,selected+1][case//12%4];coverage['aliases']+=1
        h.write(remaining,pack([0,1,2,16,0xffffffff,0x80000000,0x7fffffff][case%7]));h.write(pending,pack([0,1<<(case//7%16),0xffff,0xffffffff,rng.getrandbits(32)][case//7%5]))
        if case%3:h.write(deferred,bytes([case//2%2]));h.write(selected,struct.pack('<H',case&0xffff))
        allowed=[0,0xffff,0xffffffff,0x55555555,0xaaaaaaaa,rng.getrandbits(32)][case//5%6];reserve=[0,1,255][case//4%3];local=[case%16,0xffffffff,16][case//3%3]
        h.call('select_routes',0x56790,dict(ebx=remaining,edx=pending),[allowed,selected,reserve,local,deferred],lambda:fn(h.memory,remaining,pending,allowed,selected,reserve,local,deferred))
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-game-route-select-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_game_route_select.c','include/halo2/network_game_route_select.h','tests/network_game_route_select_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original 16-peer route selection, full memory and stack purge. Signed capacity gates, reserve-last-slot and local-ID exclusion, allowed/pending masks, early deferral and overlapping count/mask/selected/deferred outputs. No routing wrapper or whole activity query.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
