#!/usr/bin/env python3
"""Reservation expiration against original instructions, including reentrant clocks."""
import argparse, ctypes as C, hashlib, json, random, struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT, Memory, EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations, Ticks

def suite(h):
    session=h.table; first=session+0x7668; rng=random.Random(0x62de0)
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    original=[];native=[];case=0;coverage={'clock':0,'expired':0,'retained':0}
    def event(read,write,events):
        events.append(bytes(read(first,0x240)))
        if case%3==0:
            # Mutate all slots so both the captured timestamp and reloaded limit matter.
            for i in range(16):
                write(first+i*36+28,pack(0x80000000))
                write(first+i*36+32,pack([0,100,0xffffffff][(case+i)%3]))
        if case%5==0:
            write(0x510548,b'\1');write(0x51054c,pack(101))
        return [0,100,101,0x80000000,0xffffffff][case%5]
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    callback=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations();clock.ticks=callback
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);value=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    fn=h.lib.h2_network_session_expire_reservations;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];fn.restype=None
    for case in range(1024):
        original.clear();native.clear();h.write(session,rng.randbytes(0x7900))
        h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack([0,100,101,0x80000000,0xffffffff][case%5]))
        for i in range(16):
            h.write(first+i*36,bytes([0,1,128,255][(case+i)%4:][:1]))
            h.write(first+i*36+28,pack([0,1,99,100,101,0x7fffffff,0x80000000,0xffffffff][(case//4+i)%8]))
            h.write(first+i*36+32,pack([0,1,99,100,101,0x7fffffff,0x80000000,0xffffffff][(case//32+i)%8]))
        before=h.read(first,0x240)
        h.call('session_expire_reservations',0x62de0,dict(eax=session),[],lambda:fn(h.memory,C.byref(clock),session),None)
        assert original==native,case
        coverage['clock']+=len(original)
        after=h.read(first,0x240)
        for i in range(16):
            if before[i*36]:coverage['retained' if after[i*36] else 'expired']+=1
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-reservation-expiry-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    sources=['src/network_session_reservation_expiry.c','include/halo2/network_session_reservation_expiry.h','tests/network_session_reservation_expiry_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:sha(ROOT/s) for s in sources},scope='Original instructions; all sixteen slots, cached/SDK clocks, unsigned strict expiration and wrapping subtraction, inactive and infinite-duration gates, callback mutation of timestamps/limits/cache; full guest memory and callback snapshots. No live session claim.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
