#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    observer=h.table;rng=random.Random(0x79480);original=[];native=[];counts={'ticks':0,'active':0,'positive':0,'idle':0,'busy':0,'minimum':0}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append(bytes(read(observer,0x5000)))
        if log is original:counts['ticks']+=1
        n=len(log);e=observer+0xa8+((n+case)%15)*0x528
        if case%3==0:write(e,pack(1));write(e+0x48c,b'\1');write(e+0x4a4,pack(1000));write(e+0x4b0,pack(0x80000000))
        if case%7==0:write(observer+0x4f38,pack(100))
        if case%11==0:write(0x510548,b'\1');write(0x51054c,pack(2000))
        return ([0,1000,0xfffffff0,0x80000000][case%4]+n)&0xffffffff
    tick=Ticks(lambda ctx:event(h.read,nw,native));ops=Operations(None,tick,Provider())
    labels={0x794cd:'active',0x794e8:'positive',0x79515:'idle',0x7951d:'busy',0x79528:'minimum'}
    def hook(u,at,size,data):
        if at!=0x3314b0:counts[labels[at]]+=1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);v=event(u.mem_read,u.mem_write,original);u.reg_write(X.UC_X86_REG_EAX,v);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,*labels]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_finish_cycle;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];fn.restype=None
    for case in range(512):
        original.clear();native.clear();h.write(observer,rng.randbytes(0x5000))
        for i in range(15):
            e=observer+0xa8+i*0x528;h.write(e,pack(0 if (case+i)%5==0 else 1));h.write(e+0x48c,bytes([0 if (case+i)%7==0 else 1]));h.write(e+0x50c,bytes(3) if (case+i)%2 else rng.randbytes(3));h.write(e+0x4a0,bytes(3) if (case+i)%3 else b'\1\2\4')
            for off in [0x4a4,0x4a8,0x4b0,0x4f0,0x518,0x51c]:h.write(e+off,pack([0,1,1000,0xffffffff,0x80000000,0x7fffffff][(case+i+off)%6]))
        h.write(observer+0x4f38,pack([0,1000,0xfffffff0,0x80000000][case//4%4]));h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack([0,1000,0xffffffff,0x80000000][case//2%4]))
        h.call('finish_cycle',0x79480,{},[observer],lambda:fn(h.memory,C.byref(ops),observer))
        assert original==native,case
    assert all(counts.values()),counts
    return counts

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-cycle-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    files=['src/network_observer_cycle.c','include/halo2/network_observer_cycle.h','src/network_observer_probe_result.c','tests/network_observer_cycle_oracle.py']
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original 15-slot cycle finalization with actual counter measurements; full memory and SDK clock snapshots. Active/inactive slots, positive/nonpositive measurements, flag accumulation, counters wrapping, signed minima, callback activation of later slots and clock override changes. No whole observer update.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
