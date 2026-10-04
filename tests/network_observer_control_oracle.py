#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks,Provider
CB=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class Callbacks(C.Structure):_fields_=[('context',C.c_void_p),('invoke',CB)]
def suite(h,frame_context=None):
    o=h.table;config=o+0x6000;pool=o+0x7000;scratch=o+0x9000;obj=o+0xa000;vt=obj+64;target=0x3000f00;lookup=0x3000e00;session=o+0xb000
    rng=random.Random(0x78ac0);pack=lambda v:struct.pack('<I',v&0xffffffff);original=[];native=[];coverage={'virtual':0,'ticks':0,'priority':0,'commit':0,'probe':0,'lookup':0,'allocate':0,'activity':0,'reduce':0,'started':0,'result':0,'success':0,'restore':0,'routed_activity':0}
    def event(read,write,log,kind,index=0):
        log.append((kind,index,bytes(read(o,0x5000))))
        if log is original:coverage[kind]+=1
        if kind=='virtual' and case%3==0:write(o+0xa8+((index+1)%15)*0x528+9,b'\0')
        return 1000 if kind=='ticks' else (0xffffffff if index%3==0 else index) if kind=='lookup' else index%2
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks'));ops=Operations(None,tick,Provider())
    cb=CB(lambda ctx,fn,object,index:event(h.read,nw,native,'lookup' if fn==lookup else 'virtual',index));callbacks=Callbacks(None,cb)
    labels={0x7a2a0:'priority',0x79260:'commit',0x7a330:'probe',0x78e60:'allocate',0x54890:'activity',0x79c00:'reduce',0x7a03d:'started',0x7a1c0:'result',0x7a3f6:'success',0x7a110:'restore',0x54977:'routed_activity'}
    def hook(u,at,size,ctx):
        if at in labels:coverage[labels[at]]+=1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);index=struct.unpack('<I',u.mem_read(sp+4,4))[0] if at in [target,lookup] else 0
        v=event(u.mem_read,u.mem_write,original,'lookup' if at==lookup else 'virtual' if at==target else 'ticks',index)
        u.reg_write(X.UC_X86_REG_EAX,v);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+(8 if at in [target,lookup] else 4))
    h.u.mem_write(target,b'\xc2\x04\x00');h.u.mem_write(lookup,b'\xc2\x04\x00')
    for at in [target,lookup,0x3314b0,*labels]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_control_bandwidth;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Callbacks),C.c_uint32,C.c_uint32];fn.restype=None
    if frame_context is not None:
        frame_context.tick.contents.clock=C.cast(C.pointer(ops),C.c_void_p).value
        frame_context.control=C.pointer(callbacks);frame_context.control152=scratch
        fn=h.lib.h2_network_observer_frame;fn.argtypes=[C.POINTER(Memory),C.POINTER(type(frame_context)),C.c_uint32];fn.restype=None
    for case in range(832):
        original.clear();native.clear();h.write(o,bytes(0x5000));h.write(config,bytes(0x200));h.write(pool,bytes(15*0xf8));h.write(o+16,pack(config));h.write(o+0x14,pack(obj));h.write(obj,pack(vt));h.write(vt+4,pack(target));h.write(0x4d87d4,pack(pool));h.write(o+0x4e00,bytes([case%5!=0]));h.write(0x4c99b8,b'\0');h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack(1000))
        for off,val in [(0x148,0 if case%3 else 2000),(0x19c,2000),(0x1a4,2000),(0x1a0,2000),(0x1ec,1),(0x1f0,100),(0x1c0,4),(0x1c4,0x3f000000),(0x1c8,100),(0x1cc,1),(0x1d0,0),(0x1d4,100),(0x1d8,100),(0x1e0,2),(0x1e4,3),(0x150,16000),(0x9c,4),(0x108,24),(0x10c,40)]:h.write(config+off,pack(val))
        h.write(config+0xa0,struct.pack('<ffff',8,4,2,1));h.write(config+0x110,struct.pack('<f',30))
        for i in range(15):
            e=o+0xa8+i*0x528;h.write(e,pack(1 if (i+case)%4 else 0));h.write(e+9,b'\1');h.write(e+12,pack(i));h.write(e+0x48c,bytes([0 if (case+i)%7==0 else 1]));h.write(pool+i*0xf8+0x54,pack(5));h.write(e+0x494,pack(16000));h.write(e+0x498,pack(512));h.write(e+0x49c,struct.pack('<f',1));h.write(e+0x4dc,pack((i+case)%2));h.write(e+0x4e0,pack(0xffffffff));h.write(e+0x4e8,pack(0xffffffff));h.write(e+0x518,pack(2))
        for off,val in [(0x14c,32),(0xe0,1),(0x158,16000),(0x15c,64000),(0x160,64000),(0x164,8000),(0x16c,100),(0x194,100),(0x198,0x3e800000),(0x1dc,100)]:h.write(config+off,pack(val))
        h.write(o+0x4e04,pack(128000));h.write(o+0x4f34,pack(0xffffffff))
        if case%9==0:
            e=o+0xa8+0x528;h.write(e+0x4f4,b'\1');h.write(e+0x4f8,pack(16000));h.write(e+0x4fc,pack(512));h.write(e+0x500,struct.pack('<f',1));h.write(e+0x4b0,pack(1000));h.write(e+0x504,pack(0))
        h.write(session,bytes(0x7800));h.write(session,pack(vt));h.write(vt+0x14,pack(lookup));h.write(session+0x741c,pack(5));h.write(session+0x72d8,pack(1));h.write(0x527364,pack(session));h.write(0x52736c,pack(session));h.write(0x527330,b'\1');h.write(0x4c99b8,bytes([case%4!=0]));h.write(0x476fcc,b'\1');h.write(0x4c9888,pack(1));h.write(0x4c988c,pack(1+case%2));h.write(0x4c9878,pack(1))
        if case>=384:
            for off,val in [(0x1a0,0 if case%2 else 2000),(0x150,32000),(0x18c,4000),(0x190,0x3e800000),(0x1a4,0),(0x19c,0)]:h.write(config+off,pack(val))
            for i in range(15):
                e=o+0xa8+i*0x528;h.write(e+0x4dc,pack(1+i%3));h.write(e+0x4a0,b'\1\1\1');h.write(e+0x4a8,pack(1000));h.write(e+0x508,pack(0));h.write(e+0x4b0,pack(0));h.write(e+0x4b4,pack(0));h.write(e+0x504,pack(0));h.write(e+0x4f4,b'\1');h.write(e+0x4f8,pack(16000));h.write(e+0x4fc,pack(512));h.write(e+0x500,struct.pack('<f',1))
        if case>=768:
            h.write(0x4c99b8,b'\1');h.write(0x4c988c,pack(1));h.write(0x4c9878,pack(1));h.write(0x4c987c,pack(1));h.write(0x4c9880,pack(4));h.write(session+0x72d8,pack(0));h.write(session+0xf4,pack(3));h.write(session+0x111c,pack(3));h.write(session+0x112c,pack(0));h.write(session+0x1268,pack(1));h.write(0x4c9988,bytes(32));h.write(0x5259b8,b'\1');h.write(0x5259bc,pack(2));h.write(0x527104,b'\1')
        if frame_context is not None:
            for off in [0x6c,0x74,0x80,0x84,0x118]:h.write(config+off,pack(2000))
            for i in range(15):
                e=o+0xa8+i*0x528;h.write(e+8,b'\x08');h.write(e+0x70,pack(0xffffffff))
        h.write(scratch,rng.randbytes(152));saved=h.read(scratch,152)
        def run():
            if frame_context is None:fn(h.memory,C.byref(ops),C.byref(callbacks),o,scratch)
            else:fn(h.memory,C.byref(frame_context),o)
            nw(scratch,saved)
        h.call('control' if frame_context is None else 'frame_control',0x78ac0 if frame_context is None else 0x75da0,{},[o],run);assert original==native,case
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-control-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_observer_control.c','include/halo2/network_observer_control.h','tests/network_observer_control_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Expanded controller composition: full persistent memory and clock/consumer snapshots; existing active entries, disabling, consumer mask mutation, priority sorting, readiness and cooldown, actual probe/commit callees, probe starts, result evaluation, successful probes and restoration. Disjoint 152-byte scratch excluded. Allocation, game-session virtual lookup and actual activity predicate (ID-match shortcut and routed activity), and bandwidth reduction exercised. Virtual implementations and clock controlled. Routed activity also executes within the controller; no live network or whole-game claim.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
