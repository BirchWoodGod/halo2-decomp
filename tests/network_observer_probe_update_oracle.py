#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x7a330);observer=h.table;config=observer+0x5000;alternate=config+0x300;output=config+0x600;original=[];native=[];coverage={}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append(bytes(read(observer,0x5000)))
        if log is original:coverage['ticks']=coverage.get('ticks',0)+1
        if case%5==0:write(observer+16,pack(alternate));write(entry+0x494,pack(16000));write(entry+0x498,pack(512))
        if case%7==0:write(observer+0x4f38,pack(777));write(entry+0x4a8,pack(12345));write(entry+0x49c,struct.pack('<f',1.25))
        if case%11==0:write(entry+0x4a0,b'\1\1\1')
        return [0,1000,0xfffffff0,0x80000000][case//2%4]+len(log)
    tick=Ticks(lambda ctx:event(h.read,nw,native)&0xffffffff);clock=Operations(None,tick,Provider())
    labels={0x7a39e:'ready',0x7a3f6:'success',0x7a3dc:'reduce',0x7a3ea:'restore',0x7a45c:'failure',0x7a485:'reset',0x79eff:'exhausted',0x79f46:'limit_measure',0x79f9f:'burst',0x79fb7:'budget',0x79fcf:'rate',0x7a00b:'rate_budget',0x7a03d:'started',0x7a0e5:'timestamp'}
    def hook(u,at,size,data):
        if at!=0x3314b0:
            label=labels[at];coverage[label]=coverage.get(label,0)+1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);v=event(u.mem_read,u.mem_write,original)&0xffffffff;u.reg_write(X.UC_X86_REG_EAX,v);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,*labels]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_update_probe;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*3;fn.restype=None
    for case in range(1536):
        original.clear();native.clear();h.write(observer,bytes(0x5000));index=case%15;entry=observer+0xa8+index*0x528;h.write(entry,rng.randbytes(0x528));h.write(observer+16,pack(config));h.write(output,rng.randbytes(8))
        budget=[32,8000,16000,0x7fffffff][case//4%4];h.write(entry+0x494,pack(budget));h.write(entry+0x498,pack([0,32,1000,0x7fffffff][case//8%4]));h.write(entry+0x49c,pack([0,0xbf800000,0x3f000000,0x3f800000,0x3fc00000,0x41000000,0x42700000,0x7f800000,0x7fc12345][case//16%9]))
        for i in range(3):h.write(entry+0x4a0+i,bytes([1 if case&(1<<i) else 0]))
        h.write(entry+0x48e,bytes([case%2]));h.write(entry+0x490,bytes([case//2%2]));h.write(entry+0x4a4,pack(rng.getrandbits(32)));h.write(entry+0x4a8,pack(rng.getrandbits(32)))
        h.write(entry+0x4dc,pack(case//3%4));h.write(entry+0x4e0,pack([0,0xffffffff,1000][case%3]));h.write(entry+0x518,pack(case%3));h.write(entry+0x51c,pack(1 if case%13==0 else 0));h.write(entry+0x4c0,bytes([1 if case%17==0 else 0]));h.write(entry+0x4d8,pack(1 if case%19==0 else 0));h.write(entry+0x4f4,b'\1');h.write(entry+0x4f8,pack(16000));h.write(entry+0x4fc,pack(512));h.write(entry+0x500,struct.pack('<f',2));h.write(entry+0x4f0,pack(100));h.write(entry+0x4b0,pack([0,100,200,400][case//4%4]));h.write(entry+0x4b4,pack(0));h.write(entry+0x504,pack(100));h.write(entry+0x508,pack(0));h.write(entry+0x4ec,pack(0))
        for n,cfg in enumerate([config,alternate]):
            h.write(cfg,bytes(0x200));h.write(cfg+0x9c,pack(4));h.write(cfg+0xa0,struct.pack('<ffff',8,4,2,1));h.write(cfg+0x108,pack(24)+pack(40));h.write(cfg+0x110,struct.pack('<f',30));h.write(cfg+0x144,bytes([case%3]));h.write(cfg+0x150,pack([budget,32000,0x7fffffff][case//3%3]));h.write(cfg+0x18c,pack([0,100,16000][case//4%3]));h.write(cfg+0x190,struct.pack('<f',[0,0.25,0.5,1][case//5%4]));h.write(cfg+0x1a0,pack([0,100,0x7fffffff,0x80000000][(case//6+n)%4]))
        h.write(observer+0x4f38,pack([0,1000,0xfffffff0,0x80000000][case//7%4]));h.write(observer+0x4f40,pack(case//9%3));h.write(observer+0x4f44,pack(case//10%3));h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack([0,1000,0xffffffff,0x80000000][case//2%4]));h.write(0x485ac0,struct.pack('<H',[0,50,60,0xffff][case%4]))
        for cfg in [config,alternate]:
            for off,v in [(0x1e0,2),(0x1e4,3),(0x1e8,10),(0x1ec,1),(0x1f0,100),(0x1d4,0),(0x1d8,100),(0x14c,32),(0xe0,1),(0x194,100),(0x198,0x3e800000)]:h.write(cfg+off,pack(v))
        out=output
        saved=h.read(out,1)
        def run():
            fn(h.memory,C.byref(clock),observer,index,out)
            nw(out,saved)
        h.call('update_probe',0x7a330,dict(eax=observer),[index],run)
        assert original==native,case
    assert all(coverage.get(k) for k in ['ready','success','reduce','restore','failure','reset','started','ticks']),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-probe-update-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_probe_update.c','include/halo2/network_observer_probe_update.h','src/network_observer_probe_start.c','include/halo2/network_observer_probe_start.h','src/network_observer_probe_result.c','src/network_observer_rates.c','src/network_observer_metrics.c','tests/network_observer_probe_update_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((lib.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,coverage=coverage,source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},scope='Original per-slot probe controller with actual engine callees. Full persistent memory and clock snapshots, state transitions, restoration, reduction, failure, initiation and reset. Disjoint native scratch excluded from persistent comparison. Valid integer divisors/default floating environment; no whole observer loop.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
