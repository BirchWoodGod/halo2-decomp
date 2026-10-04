#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE

def suite(h):
    rng=random.Random(0x53c70);a=h.table;b=a+0x8000;scratch=b+0x8000
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    coverage={'find_peer':0,'matched':0,'nonzero':0,'selection':0}
    def hook(u,at,size,ctx):coverage['selection' if at==0x56790 else 'find_peer' if at==0x5f760 else 'matched']+=1
    for at in [0x5f760,0x53d01,0x56790]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    kind=h.lib.h2_network_game_session_kind;kind.argtypes=[C.POINTER(Memory)];kind.restype=C.c_uint32
    fn=h.lib.h2_network_game_member_routes;fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4;fn.restype=None
    for case in range(1024):
        h.write(0x527364,pack(a));h.write(0x52736c,pack(b));h.write(0x527330,bytes([case%7!=0]));h.write(0x4c99b8,bytes([case%11!=0]));h.write(0x476fcc,bytes([case%13!=0]));h.write(0x4c988c,pack([0,1,2,2,2,0xffffffff][case%6]))
        for i,p in enumerate([a,b]):
            h.write(p+0x741c,pack((case+i)%4));h.write(p+0x4c,pack(0xffffffff if i==0 and case%17==0 else 0));h.write(p+0x54,pack([0,1,4,16,33,40,0xffffffff,0x80000000][(case//3+i)%8]))
            for j in range(40):h.write(p+0x58+j*0x10c,rng.randbytes(36))
        for j in range(40):
            if (j+case)%3:h.write(b+0x58+j*0x10c,h.read(a+0x58+(j%16)*0x10c,36))
        table=scratch+64;out=scratch+80
        h.write(table,bytes([case%5!=0]));h.write(out,rng.randbytes(4))
        for p in [a,b]:
            h.write(p+0x72d8,pack([0,1,15,0xffffffff][case//4%4]))
            for j in range(16):h.write(p+0xf4+j*0x10c,pack([0,0xffff,0xffffffff,0x5555,0xaaaa][(case+j)%5]))
        h.write(0x4c9888,pack([0,1,2,3,4][case//3%5]));h.write(0x4c9880,pack([0,1,2,16,0xffffffff][case//5%5]));h.write(0x4c9884,pack([0,1,2,16,0xffffffff][case//7%5]));h.write(0x4c9878,pack([0,1,15,0xffffffff][case//8%4]));h.write(0x4c987c,pack(case//9%4))
        for p in [a,b]:
            h.write(p+0x111c,pack([0,0xffff,0xffffffff][case%3]))
            for j in range(16):h.write(p+0x112c+j*0x13c,pack([0,1,2,15,31,32,0xffffffff][(case+j)%7]))
        requested=[0,1,0xffff,0xffffffff,0xaaaa,0x5555,rng.getrandbits(32)][case%7]
        output=table if case%19==0 else out
        h.write(scratch,rng.randbytes(24));saved=h.read(scratch,24)
        def run():
            fn(h.memory,requested,table,output,scratch);C.memmove(h.pointer+scratch-BASE,saved,24);coverage['nonzero']+=bool(h.u32(output))
        h.call('kind',0x54f20,{},[],lambda:kind(h.memory),0xffffffff)
        h.call('member_routes',0x56590,dict(eax=requested,edi=table,esi=output),[],run)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-game-member-routes-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_game_member_routes.c','include/halo2/network_game_member_routes.h','src/network_game_peer_mask.c','src/network_game_routes.c','include/halo2/network_game_routes.h','src/network_game_route_select.c','src/network_game_route_queries.c','src/network_game_overlap.c','include/halo2/network_game_overlap.h','src/network_game_session.c','src/network_session.c','tests/network_game_member_routes_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original member routing wrapper with actual peer conversion, queries, overlap and route selection. Full persistent memory/EAX; 24-byte disjoint stack replacement restored. Gates, failed getters, invalid A descriptor, signed counts, repeated identities, absent identities, B counts up to 40 and wrapped output bits. Valid B descriptor on successful getters; no fault emulation or whole activity query. Includes reserve modes, capacity, masks and output aliasing table enable flag.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
