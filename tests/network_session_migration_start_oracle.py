#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE,STACK
from network_state_oracle import Operations,Ticks
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    f=h.lib.h2_network_session_begin_migration
    f.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];f.restype=None
    rng=random.Random(0x616e0);session=h.table;scratch=session+0x8100
    frame=((STACK+0x8000-4)&~7)-0x118
    original=[];native=[];captured=[];case=0;coverage={'cached':0,'one_tick':0,'two_ticks':0,'wide_shift':0}
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events,local):
        events.append((bytes(read(session,0x7900)),bytes(read(local,0x118)),bytes(read(0x510548,8))))
        n=len(events)
        if case%3==0:write(0x510548,b'\1');write(0x51054c,P(0xffffffff))
        write(session+0x7650,P(0xffffffff if case%5==0 else case))
        write(session+0x40,P((case+n)%16));write(session+0x72d8,P((case+n+3)%16))
        if n==2:
            values=[31,32,63,255,0xffffffff,0x80000000]
            write(session+0x40,P(values[case%6]));write(session+0x72d8,P(values[(case+1)%6]))
        return (0xffffff00+case+n)&0xffffffff
    cb=Ticks(lambda ctx:event(h.read,nw,native,scratch));ops=Operations();ops.ticks=cb
    def hook(u,addr,size,ctx):
        if addr==0x617aa:captured.append(bytes(u.mem_read(frame,0x118)));return
        value=event(u.mem_read,u.mem_write,original,frame);esp=u.reg_read(X.UC_X86_REG_ESP)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    for addr in [0x3314b0,0x617aa]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=addr,end=addr)
    for case in range(768):
        h.write(session,rng.randbytes(0x8300));h.write(session+0x40,P(case%16));h.write(session+0x72d8,P(case//16%16));h.write(session+0x7650,P(0xffffffff if case%5==0 else rng.getrandbits(32)))
        override=[0,0,1,255][case%4];h.write(0x510548,P(override)+P(rng.getrandbits(32)));seed=h.read(scratch,0x118)
        original.clear();native.clear();captured.clear()
        def run():
            f(h.memory,C.byref(ops),session,scratch)
            assert len(captured)==1 and h.read(scratch,0x118)==captured[0],case
            nw(scratch,seed)
        h.call('begin_migration',0x616e0,{},[session],run)
        assert original==native,(case,'callback snapshots')
        coverage[['cached','one_tick','two_ticks'][len(original)]]+=1
        coverage['wide_shift']+=len(original)==2
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-migration-start-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    files=['src/network_session_migration_start.c','include/halo2/network_session_migration_start.h','src/network_session_migration_payload.c','include/halo2/network_session_migration_payload.h','tests/network_session_migration_start_oracle.py','tests/network_state_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Migration entry with actual payload builder; SDK clock controlled. Full persistent memory, stack purge, original temporary state and callback snapshots. Cached and SDK clocks, callback override/index/generation mutation, generation wrap, masked wide peer shifts. Disjoint scratch; no live migration or playable startup.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
