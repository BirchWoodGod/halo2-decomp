#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE

def suite(h):
    rng=random.Random(0x53de0);a=h.table;b=a+0x8000;scratch=b+0x8000
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    counts={'zero':0,'nonzero':0}
    table=scratch+0x1000
    for name,address,mask,indexed in [('matching_members',0x54d20,0xffffffff,False),('member_value',0x55960,0xffffffff,True)]:
        fn=getattr(h.lib,'h2_network_game_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*(3 if indexed else 1);fn.restype=C.c_uint32 if mask==0xffffffff else C.c_uint8
        for case in range(2048):
            h.write(0x527364,pack(a));h.write(0x52736c,pack(b))
            for i,p in enumerate([a,b]):
                h.write(p+0x741c,pack((case+i)%4));h.write(p+0x4c,pack(0xffffffff if (case+i)%7==0 else 0));h.write(p+0x72d8,pack([0,1,0xffffffff,0x80000000][(case//3+i)%4]));h.write(p+0x111c,pack([0,0xffff,0xffffffff,0x80000001][(case//5+i)%4]))
            h.write(0x4c9988,rng.randbytes(128));h.write(0x527330,bytes([0 if case%7==0 else 255]));h.write(0x4c99b8,bytes([0 if case%11==0 else 2]));h.write(0x476fcc,bytes([0 if case%13==0 else 128]));h.write(0x4c9888,pack(0 if case%17==0 else 1));h.write(0x4c988c,pack([0,1,2,3,0xffffffff][case//8%5]));h.write(0x4c9878,pack([0,1,0xffffffff,0x80000000][case//3%4]))
            for p in [a,b]:
                for j in range(16):h.write(p+0x112c+j*0x13c,pack([0,1,0xffffffff,0x80000000][(case+j)%4]))
            h.write(table,bytes([case%3])+bytes(3)+b''.join(pack(rng.getrandbits(32)) for _ in range(64)))
            index=case%64;h.write(scratch,rng.randbytes(4));saved=h.read(scratch,4)
            def run():
                v=fn(h.memory,table,index,scratch) if indexed else fn(h.memory,scratch)
                C.memmove(h.pointer+scratch-BASE,saved,4);counts['nonzero' if v else 'zero']+=1
                return v
            h.call(name,address,dict(ebx=index,esi=table),[],run,mask)
    assert all(counts.values()),counts
    return counts

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-game-members-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    files=['src/network_game_members.c','include/halo2/network_game_members.h','src/network_game_queries.c','include/halo2/network_game_queries.h','src/network_game_session.c','tests/network_game_members_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original member filter and table lookup with actual session/ID/mask query callees. Full persistent memory and EAX/AL; native disjoint stack-replacement scratch restored before comparison. Gates, selectors, invalid descriptor sentinel, ID matches, member masks/flags, index shift masking (indices 0..63). Sixteen membership records, index shifts 0..63, enabled/disabled tables; no whole activity query.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
