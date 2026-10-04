#!/usr/bin/env python3
"""Original observer frame with actual recovered engine callees."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks,Provider
from network_observer_tick_oracle import Context,Request
from network_observer_control_oracle import Callbacks,CB,suite as control_suite
from async_task_create_oracle import Platform,Create
from async_tasks_oracle import Ops
class Frame(C.Structure):
    _fields_=[('tick',C.POINTER(Context)),('async_',C.POINTER(Platform)),('control',C.POINTER(Callbacks)),('records60',C.c_uint32),('control152',C.c_uint32)]
def suite(h):
    o=h.table;config=o+0x6000;pool=o+0x7000;scratch=o+0x9000
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    original=[];native=[];rng=random.Random(0x75da0)
    coverage={k:0 for k in ['retry','release','refresh','slot','tick','timeout','async','bandwidth','control','route','clock','mutations']}
    def event(read,write,log):
        log.append(bytes(read(o,0x5000)))
        if log is original:coverage['clock']+=1
        if case%4==0 and len(log)==2:
            write(o+0xa8+((case//4)%15)*0x528,pack(0))
            if log is original:coverage['mutations']+=1
        return 1000
    tick=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,tick,Provider())
    t=Context();t.clock=C.cast(C.pointer(clock),C.c_void_p).value;t.request=Request();t.query4=scratch;t.detach16=scratch+4;t.resolution28=scratch+20;t.message8=scratch+48;t.storage8=scratch+56;t.packet=scratch+0x1000
    workspace=(C.c_uint8*28)();t.workspace28=workspace
    tasks=Ops();async_=Platform();async_.tasks=C.pointer(tasks);async_.scratch=scratch+0x3000
    callbacks=Callbacks(None,CB());ctx=Frame(C.pointer(t),C.pointer(async_),C.pointer(callbacks),scratch+64,scratch+128)
    labels={0x77580:'retry',0x76ef0:'release',0x76f50:'refresh',0x76ff0:'slot',0x776a0:'tick',0x773a0:'timeout',0x77480:'async',0x779f0:'bandwidth',0x78ac0:'control',0x7a4a0:'route'}
    def hook(u,at,size,ctx):
        if at in labels:coverage[labels[at]]+=1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);v=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,v);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,*labels]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_frame;fn.argtypes=[C.POINTER(Memory),C.POINTER(Frame),C.c_uint32];fn.restype=None
    for case in range(256):
        original.clear();native.clear();h.write(o,bytes(0x5000));h.write(config,bytes(0x200));h.write(pool,bytes(15*0xf8));h.write(o+16,pack(config));h.write(0x4d87d4,pack(pool));h.write(0x510548,b'\0');h.write(0x4c99b8,bytes([case%2]));h.write(0x4cf73c,b'\0');h.write(0x4c987c,pack(0xabcdef01));h.write(0x4cf568,pack(2000));h.write(0x4cf56c,pack(2000))
        for off,val in [(0,1),(4,2000),(0x6c,2000),(0x118,0 if case%3 else 2000),(0x148,0 if case%2 else 2000),(0x19c,2000),(0x1a4,2000),(0x1c0,4)]:h.write(config+off,pack(val))
        if case:
            for i in range(15):
                e=o+0xa8+i*0x528;mode=(i+case)%5
                if mode==0:continue
                h.write(e,pack(1 if mode!=2 else 2));h.write(e+8,b'\x08');h.write(e+9,bytes([1 if mode<3 else 0]));h.write(e+12,pack(0xffffffff if mode==4 else i));h.write(e+0x70,pack(0xffffffff))
                if mode==3:h.write(e+0x5c,pack(0x01020304));h.write(e+0x6e,struct.pack('<H',4))
        h.write(scratch,rng.randbytes(280));saved=h.read(scratch,280)
        def run():fn(h.memory,C.byref(ctx),o);nw(scratch,saved)
        h.call('frame',0x75da0,{},[o],run);assert original==native,case
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-frame-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    comparisons=dict(h.counts);h=Harness(lib)
    t=Context();tasks=Ops();async_platform=Platform();async_platform.tasks=C.pointer(tasks);cb=Callbacks()
    ctx=Frame(C.pointer(t),C.pointer(async_platform),C.pointer(cb),h.table+0x16000,h.table+0x9000)
    try:coverage['active_control']=control_suite(h,ctx)
    finally:h.close()
    comparisons.update(h.counts)
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    files=['src/network_observer_frame.c','include/halo2/network_observer_frame.h','tests/network_observer_frame_oracle.py','tests/network_observer_control_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=comparisons,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Initial frame composition: inactive, waiting states 1/2, unowned retry/deferred retry/release, clock mutation of slot state, bandwidth and controller with bandwidth disabled, and global route mode. All engine callees execute; only SDK clock controlled. Full persistent memory and clock snapshots compared, 280 bytes of disjoint replacement stack scratch excluded. Additional 832 controller fixtures run through the complete outer frame with waiting slots, connected transport records, allocation, sorting, probe start/result/restore and routed activity. SDK clock and virtual implementations controlled. These fixtures keep the preceding bandwidth estimator on its cooldown. Asynchronous task work, connection transitions, live networking and gameplay remain unvalidated in this frame suite.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
