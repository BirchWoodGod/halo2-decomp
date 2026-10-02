#!/usr/bin/env python3
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT, Memory, EXPECTED
from network_state_oracle import Operations, Ticks, Provider

def suite(h):
    rng=random.Random(0x779f0);o=h.table;config=o+0x6000;connections=o+0x6500
    objects=o+0x7500;streams=o+0x8000
    original=[];native=[];coverage={'ticks':0,'body':0,'statistics':0,'decrease':0,'increase':0,'budget':0,'unlimited':0}
    branch_names={0x77a22:'body',0x77ae5:'statistics',0x77b5e:'decrease',0x77c14:'increase',0x77caa:'budget',0x77e2a:'unlimited'}
    def branch(u,address,size,ctx):coverage[branch_names[address]]+=1
    for address in branch_names:h.u.hook_add(U.UC_HOOK_CODE,branch,begin=address,end=address)
    def put(a,d):C.memmove(h.pointer+a-BASE,d,len(d))
    def tick(read,write,events):
        events.append(bytes(read(o+0x4e00,0x130)))
        if mutate and len(events)==1:
            write(o+16,struct.pack('<I',config+0x200))
            write(o+0x4f08,struct.pack('<I',now+10000))
        if mutate and len(events)==2:
            write(o+0x4f10,struct.pack('<I',0x7fffffff))
        return now+len(events)*7
    cb=Ticks(lambda ctx:tick(h.read,put,native));ops=Operations(None,cb,Provider())
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);result=tick(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    fn=h.lib.h2_network_observer_update_bandwidth
    fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];fn.restype=None
    def w(a,v):h.write(a,struct.pack('<I',v&0xffffffff))
    def f(a,v):h.write(a,struct.pack('<f',v))
    for case in range(1024):
        h.write(o,rng.randbytes(0xc000));now=2000+case*3;mutate=bool(case%3)
        active=case%5!=0
        w(o+16,config);h.write(o+0x4e00,bytes([active]));w(0x4d87d4,connections);w(0x4d87d8,streams)
        h.write(0x510548,bytes([case%2]));w(0x51054c,now)
        h.write(0x485ac0,struct.pack('<H',[0,30,50,60,0xffff][case%5]))
        for p in [config,config+0x200]:
            w(p+0x118,0 if case%7 else 10000)
            for off in [0x100,0x120,0x12c,0x128,0x130,0x124,0x138,0x13c,0x140,0xe0]:
                w(p+off,rng.choice([0,1,2,10,100,1000,0xffffffff,0x7fffffff,0x80000000]))
            w(p+0x9c,4);w(p+0x10c,rng.choice([0,1,2,100,0xffffffff]))
            for i in range(4):f(p+0xa0+i*4,rng.choice([0.0,-0.0,0.25,0.5,1.0,2.0,10.0,-1.0,float('inf'),float('-inf'),float('nan')]))
            f(p+0x104,rng.choice([0.0,0.1,1.0,10.0]));f(p+0x11c,rng.choice([0.0,0.5,1.0]))
            f(p+0x110,rng.choice([0.0,0.5,1.0,2.0]))
        w(o+0x4f08,1000);w(o+0x4f0c,1000)
        for off in [0x4f10,0x4f14,0x4e20,0x4e24,0x4e28]:w(o+off,rng.choice([0,1,10,100,1000,100000,0x7fffffff,0x80000000]))
        h.write(o+0x4f18,bytes([case%2]))
        h.write(o+0x4e30,bytes(0xd4))
        w(o+0x4e40,1000);w(o+0x4e50,1000);w(o+0x4e58,case%20)
        w(o+0x4e48,rng.choice([0,100,1000,0x7fffffff]));w(o+0x4f00,rng.choice([0,100,1000,0x7fffffff]))
        f(o+0x4e54,rng.choice([0.0,0.01,1.0,10.0,1e20,float('inf'),float('-inf'),float('nan')]))
        for i in range(15):
            e=o+0xa8+i*0x528;connection=connections+i*0xf8
            w(e,rng.choice([0,7,7]));w(e+12,0xffffffff if rng.randrange(4)==0 else i)
            w(e+0x46c,rng.choice([0,1,100,0xffffffff]))
            w(e+0x468,rng.choice([0,1,100,0xffffffff,0x7fffffff]))
            w(e+0x360,rng.choice([0,1,100,0xffffffff,0x7fffffff]))
            w(connection+0x3c,objects+i*64 if rng.randrange(4) else 0)
            h.write(objects+i*64+0x30,bytes([i%2]))
            w(connection+0x54,rng.choice([2,4,5,5]));h.write(connection+0x48,bytes([8 if i%3 else 0]));w(connection+0x10,i%4)
        for i in range(4):
            w(streams+i*0x97c+0x96c,rng.getrandbits(32));w(streams+i*0x97c+0x970,rng.getrandbits(32))
        original.clear();native.clear()
        h.call('bandwidth',0x779f0,dict(edi=o),[],lambda:fn(h.memory,C.byref(ops),o))
        assert original==native,case
        coverage['ticks']+=len(original)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/network-observer-bandwidth-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_bandwidth.c','include/halo2/network_observer_bandwidth.h','src/network_endpoint.c','tests/network_observer_bandwidth_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),coverage=coverage,
        source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original bandwidth update and statistics helper instructions, full memory and clock snapshots; signed thresholds, wrapped integer arithmetic, rate selection, negative budgets, estimate overflow, active slots, stream budgets, callback config mutation. Default floating rounding; SDK clock controlled.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
