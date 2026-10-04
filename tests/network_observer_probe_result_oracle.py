#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x7a1c0);observer=h.table;config=observer+0x5000;alternate=config+0x300;original=[];native=[];coverage={'ticks':0,'reduce':0,'failure':0,'result0':0,'result1':0,'result2':0}
    vals=[0,1,100,1000,0x7fffffff,0x80000000,0xffffffff,0xfffffff0]
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append(bytes(read(observer,0x5000)))
        if log is original:coverage['ticks']+=1
        if case%3==0:write(observer+16,pack(alternate));write(entry+0x4a8,pack(vals[case%8]))
        if case%5==0:write(observer+0x4f38,pack(777));write(entry+0x4b4,pack(vals[case//5%8]))
        return (vals[case//2%8]+len(log))&0xffffffff
    tick=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,tick,Provider())
    def hook(u,at,size,data):
        if at in [0x79c00,0x7a160]:coverage['reduce' if at==0x79c00 else 'failure']+=1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);v=event(u.mem_read,u.mem_write,original);u.reg_write(X.UC_X86_REG_EAX,v);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,0x79c00,0x7a160]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    for name,addr in [('measure_rate_a',0x79560),('measure_rate_b',0x795b0),('probe_failure',0x7a160),('probe_result',0x7a1c0)]:
        fn=getattr(h.lib,'h2_network_observer_'+name);fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];fn.restype=None if name=='probe_failure' else C.c_uint32
        for case in range(1024):
            original.clear();native.clear();index=case%15;entry=observer+0xa8+index*0x528;h.write(entry,rng.randbytes(0x528));h.write(observer+16,pack(config))
            for i,off in enumerate([0x4a4,0x4a8,0x4b0,0x4b4,0x4ec,0x4f0,0x504,0x508]):h.write(entry+off,pack(vals[(case//(i+1)+i)%8]))
            h.write(entry+0x48e,bytes([case%2]));h.write(entry+0x48d,b'\0');h.write(entry+0x490,b'\0');h.write(entry+0x4c0,b'\0');h.write(entry+0x4f4,b'\0');h.write(entry+0x494,pack(16000));h.write(entry+0x498,pack(1000));h.write(entry+0x4dc,pack(case%4))
            for n,cfg in enumerate([config,alternate]):
                h.write(cfg,bytes(0x200));h.write(cfg+0x9c,pack(4));h.write(cfg+0xa0,struct.pack('<ffff',60,30,15,1));h.write(cfg+0x108,pack(24)+pack(40));h.write(cfg+0x110,struct.pack('<f',30));h.write(cfg+0xe0,pack(32));h.write(cfg+0x14c,pack(8000));h.write(cfg+0x194,pack(1000));h.write(cfg+0x198,struct.pack('<f',0.25));h.write(cfg+0x1a0,pack(vals[(case//7+n)%8]));h.write(cfg+0x1d4,pack(vals[(case//3+n)%8])+pack(vals[(case//4+n)%8]));h.write(cfg+0x1e0,pack([1,2,3,17][case%4])+pack(vals[(case//6+n)%8])+pack(vals[(case//5+n)%8]))
            h.write(observer+0x4f38,pack(vals[case//8%8]));h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack(vals[case//2%8]));h.write(0x485ac0,struct.pack('<H',60))
            regs=dict(ebx=observer) if name=='probe_result' else dict(ecx=observer,**({'edi':index} if name=='probe_failure' else {'eax':index}))
            def run():
                result=fn(h.memory,C.byref(clock),observer,index)
                if name=='probe_result':coverage['result'+str(result)]+=1
                return result
            h.call(name,addr,regs,[index] if name=='probe_result' else [],run,None if name=='probe_failure' else 0xffffffff)
            assert original==native,(name,case)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-probe-result-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_probe_result.c','include/halo2/network_observer_probe_result.h','src/network_observer_reduce.c','src/network_observer_probe.c','src/network_observer_metrics.c','tests/network_observer_probe_result_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((lib.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,coverage=coverage,source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},scope='Original two counter-rate measurements, failure step and result decision with actual reduction/reset/rate helpers. Full memory and EAX where meaningful; captured timestamps, signed wraps, callback config/counter changes and all three result statuses. Valid integer divisors and default floating environment; not full probe controller.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
