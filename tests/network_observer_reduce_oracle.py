#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x79c00);observer=h.table;config=observer+0x5000;alternate=config+0x300;original=[];native=[];coverage={'clock':0,'reduce':0,'peer':0,'restore':0,'reset':0,'pending':0}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append(bytes(read(observer,0x5000)))
        if log is original:coverage['clock']+=1
        if case%3==0:write(observer+16,pack(alternate));write(entry+0x4dc,pack(3))
        if case%5==0:write(observer+0x4f34,pack(777));write(entry+0x514,pack(0x7fffffff))
        return [0,100,0xfffffff0,0x80000000,0xffffffff][case//3%5]
    tick=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,tick,Provider())
    def hook(u,at,size,data):
        if at!=0x3314b0:
            name={0x79c00:'reduce',0x79a10:'peer',0x7a110:'restore',0x79d90:'reset',0x79d17:'pending'}[at];coverage[name]+=1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);value=event(u.mem_read,u.mem_write,original);u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,0x79c00,0x79a10,0x7a110,0x79d90,0x79d17]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    for mode,address in [('reduce_peer',0x79a10),('reduce_bandwidth',0x79c00)]:
        fn=getattr(h.lib,'h2_network_observer_'+mode);fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*(3 if mode=='reduce_bandwidth' else 2);fn.restype=None
        for case in range(1024):
            original.clear();native.clear();index=case%15;entry=observer+0xa8+index*0x528;h.write(observer,rng.randbytes(0x5000));h.write(observer+16,pack(config))
            for i in range(15):
                peer=observer+0xa8+i*0x528;h.write(peer,pack(0 if (case+i)%4==0 else 4));h.write(peer+0x48c,bytes([0 if (case+i)%5==0 else 1]));h.write(peer+0x48d,bytes([case%2]));h.write(peer+0x48e,bytes([i%2]));h.write(peer+0x490,bytes([i%3]));h.write(peer+0x4c0,bytes([(case+i)%2]));h.write(peer+0x4dc,pack((case+i)%4));h.write(peer+0x4f4,bytes([1 if (case+i)%3==0 else 0]))
                for off in [0x494,0x4cc,0x4f8]:h.write(peer+off,pack([8000,16000,50000,0x7fffffff][(case+i)%4]))
                for off in [0x498,0x4d0,0x4fc]:h.write(peer+off,pack([100,1000,0x7fffffff,0xffffffff][(case+i)%4]))
                for off in [0x49c,0x500]:h.write(peer+off,pack([0x3fc00000,0x41f80000,0x7fc12345,0x7f800000][(case+i)%4]))
                for off in [0x510,0x514]:h.write(peer+off,pack([i*1000,0x7fffffff,0x80000000,0xffffffff][(case+i)%4]))
            for n,cfg in enumerate([config,alternate]):
                h.write(cfg,bytes(0x200));h.write(cfg+0x9c,pack(4));h.write(cfg+0xa0,struct.pack('<ffff',60,30.5,15.5,1.5));h.write(cfg+0x108,pack(24)+pack(40));h.write(cfg+0x110,struct.pack('<f',30));h.write(cfg+0xe0,pack(32+n*16));h.write(cfg+0x14c,pack(8000));h.write(cfg+0x194,pack([0,1000,0x7fffffff,0xffffffff][case%4]));h.write(cfg+0x198,pack([0,0x3e800000,0x3f000000,0x3f800000,0x7fc12345][case%5]));h.write(cfg+0x1b8,pack([0,100,0x7fffffff,0xffffffff][case//4%4]));h.write(cfg+0x1bc,pack(100+n*100))
            h.write(observer+0x4f34,pack([0,0xffffffff,100,0xfffffff0][case//5%4]));h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack([0,1000,0xffffffff,0x80000000][case//2%4]));h.write(0x485ac0,struct.pack('<H',[0,50,60,0xffff][case%4]));propagate=[0,1,255][case%3]
            if mode=='reduce_peer':regs=dict(eax=index);stack=[observer];args=[observer,index]
            else:regs=dict(ecx=observer);stack=[index,propagate];args=[observer,index,propagate]
            h.call(mode,address,regs,stack,lambda:fn(h.memory,C.byref(clock),*args));assert original==native,(mode,case)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-reduce-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_reduce.c','include/halo2/network_observer_reduce.h','src/network_observer_probe.c','src/network_observer_metrics.c','src/network_observer_rates.c','tests/network_observer_reduce_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((lib.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,coverage=coverage,source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},scope='Original paired peer selection/reduction with bounded recursive call and actual restore/reset/rate helpers. Full memory and clock snapshots; cooldown, signed metrics/ties, type gating, pending budgets, float-int-float rate truncation, wrapped products and callbacks. Default floating environment, valid integer divisors; no whole observer loop.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
