#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x78e60);observer=h.table;config=observer+0x5000;alternate=config+0x300;conn=observer+0x5700;provider=observer+0x5900;stream=observer+0x6000
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    original=[];native=[];coverage={'ticks':0,'redistribution':0,'provider':0,'stream':0}
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append((bytes(read(observer,0x5000)),bytes(read(conn,0xf8))))
        if log is original:coverage['ticks']+=1
        if case%3==0:write(observer+16,pack(alternate))
        if case%5==0:
            peer=observer+0xa8+((index+1)%15)*0x528
            write(peer,pack(4));write(peer+0x48c,b'\1');write(peer+0x494,pack(12345));write(peer+0x498,pack(700))
        if case%7==0:write(conn+0x3c,pack(provider));write(provider+0x30,b'\0')
        return [0,1,100,0xfffffff0,0x80000000][case%5]
    tick=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,tick,Provider())
    def hook(u,at,size,data):
        if at==0x79069:coverage['redistribution']+=1;return
        if at==0x79119:coverage['stream']+=1;return
        if at==0x790bb:coverage['provider']+=1;return
        esp=u.reg_read(X.UC_X86_REG_ESP);value=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,esp));u.reg_write(X.UC_X86_REG_ESP,esp+4)
    for at in [0x3314b0,0x79069,0x79119,0x790bb]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_allocate_bandwidth;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];fn.restype=None
    for case in range(1024):
        original.clear();native.clear();index=case%15;entry=observer+0xa8+index*0x528
        h.write(observer,rng.randbytes(0x5000));h.write(conn,bytes(0xf8));h.write(provider,bytes(0x40));h.write(stream,rng.randbytes(0x97c));h.write(observer+16,pack(config));h.write(0x4d87d4,pack(conn)+pack(stream))
        h.write(conn+0x3c,pack(0 if case%3==0 else provider));h.write(provider+0x30,bytes([case%2]));h.write(conn+0x54,pack([2,4,5][case%3]));h.write(conn+0x48,pack(8 if case%4 else 0));h.write(stream+0x96c,pack([0,20,100,1000,0xffffffff][case%5]))
        for i in range(15):
            peer=observer+0xa8+i*0x528;h.write(peer,pack(0 if (case+i)%3==0 else 4));h.write(peer+12,pack(0));h.write(peer+0x48c,bytes([0 if (case+i)%4==0 else 1]));h.write(peer+0x48d,bytes([case%2]));h.write(peer+0x48e,bytes([i%2]));h.write(peer+0x490,bytes([i%3]))
            h.write(peer+0x494,pack([0,100,8000,64000,0x7fffffff,0x80000000,0xffffffff][(case//8+i)%7]));h.write(peer+0x498,pack([0,100,2000,0x7fffffff,0xffffffff][(case+i)%5]))
        for n,cfg in enumerate([config,alternate]):
            h.write(cfg,bytes(0x200));h.write(cfg+0x9c,pack(4));h.write(cfg+0xa0,struct.pack('<ffff',60,30,15,1));h.write(cfg+0x108,pack(24)+pack(40));h.write(cfg+0x110,struct.pack('<f',30));h.write(cfg+0xe0,pack(32+n*16));h.write(cfg+0x14c,pack([100,8000,64000][case%3]));h.write(cfg+0x154,pack([0,100,0x7fffffff,0x80000000][case%4]));h.write(cfg+0x158,pack([1000,32000,0x7fffffff,0xffffffff][case//4%4]));h.write(cfg+0x15c,pack(100000+n*1000)+pack(200000)+pack(16000));h.write(cfg+0x16c,pack([1,20,100,1000][case%4]))
        h.write(observer+0x4e01,bytes([case%2]));h.write(observer+0x4e04,pack([0,16000,1000000,0x7fffffff,0x80000000,0xffffffff][case//8%6]));h.write(observer+0x4f2c,pack([0,100,0xfffffff0,0x80000000][case//3%4]));h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack([0,100,0xffffffff,0x80000000][case//2%4]));h.write(0x485ac0,struct.pack('<H',[0,50,60,0xffff][case%4]))
        h.call('allocate_bandwidth',0x78e60,dict(eax=index),[observer],lambda:fn(h.memory,C.byref(clock),observer,index))
        assert original==native,(case,'clock snapshots')
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-bandwidth-allocate-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_bandwidth_allocate.c','include/halo2/network_observer_bandwidth_allocate.h','src/network_observer_metrics.c','src/network_observer_rates.c','tests/network_observer_bandwidth_allocate_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((lib.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,coverage=coverage,source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},scope='Original bandwidth allocation and actual rate selection/setter. Full memory and clock snapshots, active slots, signed/wrapped budgets/timestamps, configuration/peer/provider mutation, stream latency and provider types. Default floating environment and valid integer divisors; no division-fault equivalence or complete observer loop.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
