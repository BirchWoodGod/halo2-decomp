#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x77f90);o=h.table;config=o+0x6000
    original=[];native=[];coverage={'ticks':0,'counter':0,'smooth':0,'transition':0}
    sites={0x77fcc:'transition',0x78019:'counter',0x78069:'smooth'}
    def branch(u,a,size,ctx):coverage[sites[a]]+=1
    for a in sites:h.u.hook_add(U.UC_HOOK_CODE,branch,begin=a,end=a)
    def put(a,d):C.memmove(h.pointer+a-BASE,d,len(d))
    def event(read,write,events):
        events.append(bytes(read(o+0x4e08,0x410)))
        if mutate:
            write(o+16,struct.pack('<I',config+0x200))
            write(o+0x4e14,bytes([category]))
            write(o+0x4e10,struct.pack('<I',0xdeadbeef))
            write(o+0x4e0c,struct.pack('<I',average))
        if switch:
            write(0x510548,b'\x01');write(0x51054c,struct.pack('<I',now))
        return (now+len(events)*13)&0xffffffff
    cb=Ticks(lambda ctx:event(h.read,put,native));ops=Operations(None,cb,Provider())
    def hook(u,a,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);value=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    fn=h.lib.h2_network_observer_record_measurement
    fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*4;fn.restype=None
    def w(a,v):h.write(a,struct.pack('<I',v&0xffffffff))
    edge=[0,1,100,0xffffffff,0x80000000,0x7fffffff]
    for case in range(1536):
        h.write(o,rng.randbytes(0x6400));w(o+16,config)
        mutate=bool(case%3);switch=case%7==0;category=rng.choice([0,1,2,255])
        now=rng.choice(edge+[rng.getrandbits(32)]);average=rng.choice(edge)
        sample=rng.choice(edge+[rng.getrandbits(32)]);reference=rng.choice(edge)
        comparison=rng.choice(edge+[rng.getrandbits(32)])
        w(o+0x4e08,rng.choice(edge));w(o+0x4e0c,average);w(o+0x4e10,rng.choice(edge))
        h.write(o+0x4e14,bytes([case%2]));w(o+0x4e18,0xffffffff);w(o+0x4e1c,0x7fffffff)
        h.write(0x510548,bytes([0 if case%2 else 255]));w(0x51054c,now)
        for p in [config,config+0x200]:
            h.write(p+0x1ac,struct.pack('<f',rng.choice([0.0,-0.0,0.5,1.0,1.0000001,-1.0,float('inf'),float('-inf'),float('nan')])))
            w(p+0x1b0,rng.choice(edge));w(p+0x1b4,rng.choice([0,1,2,31,32,33,255,0xffffffff]))
        original.clear();native.clear()
        h.call('measurement',0x77f90,dict(esi=o,ecx=sample,eax=reference),[comparison],
            lambda:fn(h.memory,C.byref(ops),o,sample,reference,comparison))
        assert original==native,case
        coverage['ticks']+=len(original)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/network-observer-measurement-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_measurement.c','include/halo2/network_observer_measurement.h','tests/network_observer_measurement_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),coverage=coverage,
        source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original measurement instructions, full guest memory and clock snapshots. Signed/wrapped thresholds and smoothing, masked shift counts, NaN/infinite factors, callback changes to config/category/timestamp/average and clock override. SDK clock controlled; default floating environment.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
