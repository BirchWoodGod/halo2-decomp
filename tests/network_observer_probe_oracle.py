#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x7a2a0);observer=h.table;config=observer+0x5000;alternate=config+0x300
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    bits=lambda f:struct.unpack('<I',struct.pack('<f',f))[0]
    vals=[0,1,100,0x7fffffff,0x80000000,0xffffffff,0xfffffff0,0x1000001]
    floats=[0,0x80000000,0x3f800000,0xbf800000,0x3f000000,0x42c80000,0x7f800000,0xff800000,0x7fc12345,0x00800000,1]
    original=[];native=[];coverage={'ticks':0,'restore':0};case=0;entry=0
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append(bytes(read(observer,0x5000)))
        if log is original:coverage['ticks']+=1
        if case%3==0:write(observer+16,pack(alternate));write(entry+0x494,pack(vals[case%8]))
        if case%5==0:write(entry+0x4dc,pack(3));write(entry+0x4e8,pack(17))
        return vals[case//3%8]
    tick=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,tick,Provider())
    def hook(u,at,size,data):
        if at==0x79600:coverage['restore']+=1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);result=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,0x79600]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    for name,addr in [('reset_probe',0x79d90),('restore_probe',0x7a110),('probe_priority',0x7a2a0)]:
        fn=getattr(h.lib,'h2_network_observer_'+name)
        fn.argtypes=[C.POINTER(Memory)]+([] if name=='restore_probe' else [C.POINTER(Operations)])+[C.c_uint32]*2;fn.restype=C.c_float if name=='probe_priority' else None
        for case in range(1024):
            original.clear();native.clear();index=case%15;entry=observer+0xa8+index*0x528;h.write(entry,rng.randbytes(0x528));h.write(observer+16,pack(config))
            h.write(entry+0x4dc,pack([0,1,1,2,3,0xffffffff][case%6]));h.write(entry+0x4e8,pack(vals[case//6%8]));h.write(entry+0x494,pack(vals[case//4%8]));h.write(entry+0x4f4,bytes([[0,1,2,255][case%4]]));h.write(entry+0x500,pack(floats[case%len(floats)]))
            for i,off in enumerate([0x48d,0x48e,0x490]):h.write(entry+off,bytes([[0,1,2,255][case//(4**i)%4]]))
            for n,cfg in enumerate([config,alternate]):
                h.write(cfg+0x1c8,pack(floats[(case//8+n)%len(floats)]));h.write(cfg+0x1cc,pack(vals[(case//2+n)%8]));h.write(cfg+0x1d0,pack(floats[(case//16+n)%len(floats)]));h.write(cfg+0x110,pack(floats[(case//32+n)%len(floats)]))
            h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack(vals[case//2%8]));h.write(0x485ac0,struct.pack('<H',[0,50,60,0xffff][case%4]))
            def run():
                value=fn(h.memory,*([] if name=='restore_probe' else [C.byref(clock)]),observer,index)
                if name=='probe_priority':assert bits(value)==(h.u.reg_read(X.UC_X86_REG_XMM0)&0xffffffff),(case,hex(bits(value)),hex(h.u.reg_read(X.UC_X86_REG_XMM0)&0xffffffff))
            h.call(name,addr,dict(eax=index,**({'esi':observer} if name=='probe_priority' else {'ecx':observer})),[],run)
            assert original==native,(name,case)
    assert all(coverage.values())
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-probe-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_probe.c','include/halo2/network_observer_probe.h','src/network_observer_metrics.c','src/network_observer_rates.c','tests/network_observer_probe_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((lib.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,coverage=coverage,source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},scope='Original reset, restore and probe-priority instructions, actual rate setter/limit helper. Full memory, clock snapshots and exact XMM0 result bits. Wrapped time/product, captured timestamp, config/slot changes, all probe states, flags, quiet NaNs/infinities/subnormals. Default floating environment only.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
