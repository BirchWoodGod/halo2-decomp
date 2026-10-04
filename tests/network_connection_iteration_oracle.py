#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks,Provider
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    rng=random.Random(0x891e0);connection=h.table;provider=connection+0x1000;local=connection+0x2000
    coverage=dict(inline=0,provider=0,exhausted=0,filtered=0,aliases=0,ticks=0,override=0,stamp_alias=0)
    sites={0x89228:'inline',0x89268:'provider',0x89298:'exhausted'}
    original=[];native=[]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append(bytes(read(0x4e6398,8)));write(0x4e6398,P(0xffff0000|case));write(0x4e639c,P(0xabcdef00|case));write(0x510548,b'\1');write(0x51054c,P(0xdeadbeef));return 0x12340000|case
    tick=Ticks(lambda ctx:event(h.read,nw,native));ops=Operations(None,tick,Provider())
    def hook(u,at,size,ctx):
        if at in sites:coverage[sites[at]]+=1;return
        if at==0x89284:
            if not (u.reg_read(X.UC_X86_REG_EFLAGS)&64):coverage['filtered']+=1
            return
        coverage['ticks']+=1;sp=u.reg_read(X.UC_X86_REG_ESP);value=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,0x89284,*sites]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    next_=h.lib.h2_network_connection_next_component;next_.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];next_.restype=C.c_uint8
    stamp=h.lib.h2_network_connection_stamp;stamp.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];stamp.restype=None
    for case in range(2048):
        h.write(connection,rng.randbytes(0x100));h.write(provider,rng.randbytes(0x100));h.write(local,rng.randbytes(20));h.write(connection+0x20,P([0,1,2,3,0xffffffff][case%5]));h.write(provider+12,P([0,1,8,0xffffffff][case//5%4]));h.write(connection+0x3c,P(0 if case%7==0 else provider))
        for j in range(3):h.write(connection+0x24+j*8,P([0,0xffffffff,1,2,0x10,0x20][(case+j)%6]))
        for j in range(8):h.write(provider+16+j*8,P([0,0xffffffff,1,2,0x10,0x20][(case+j)%6]))
        iterator=local
        if case%8==0:
            iterator=connection+0x20 if case%16==0 else provider;coverage['aliases']+=1
        required=[0,1,2,3,0x10,0x30,0xffffffff][case//3%7]
        if iterator==connection+0x20:required=3
        h.write(iterator,P(required));h.write(iterator+4,P([0xffffffff,0,1,2,0x80000000,0x80000001,0x7fffffff,0xfffffffe][case//7%8]));h.write(iterator+8,P(rng.getrandbits(32)))
        if iterator==provider:h.write(provider+12,P(8))
        h.call('next_component',0x891e0,dict(ebx=connection),[iterator],lambda:next_(h.memory,connection,iterator),255)
        if iterator==local and case%11==0:
            for _ in range(12):h.call('next_component',0x891e0,dict(ebx=connection),[iterator],lambda:next_(h.memory,connection,iterator),255)
    for case in range(1024):
        original.clear();native.clear();slot=[0,1,2,5,0xfffffff7,0x10000000][case%6];target=connection
        if case%4==0:
            target=(0x4e6398-0x98-(slot<<4))&0xffffffff;coverage['stamp_alias']+=1
        h.write(0x4e6398,P(rng.getrandbits(32)));h.write(0x4e639c,P(rng.getrandbits(32)));h.write(0x510548,bytes([0 if case%3==0 else 255]));h.write(0x51054c,P(rng.getrandbits(32)))
        if case%3:coverage['override']+=1
        h.call('stamp',0x88d70,dict(esi=target,eax=slot),[],lambda:stamp(h.memory,C.byref(ops),target,slot));assert original==native,case
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-iteration-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_connection_iteration.c','include/halo2/network_connection_iteration.h','tests/network_connection_iteration_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original two-list component iterator and connection timestamp writer, full persistent memory and AL result. Inline/provider filtering, exhausted cursor restart, signed boundaries and aliased iterator outputs; timestamp wrapping slot arithmetic, destination/global aliasing, override clock and mutating SDK clock. SDK ticks controlled. Valid mapped list records only; not whole connection update or gameplay.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
