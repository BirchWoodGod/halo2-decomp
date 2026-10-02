#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from online_cancel_oracle import CancelOps,Call
from async_tasks_oracle import Ops
from allocator_oracle import Allocator,AllocFn,FreeFn

def suite(h):
    rng=random.Random(0xb3670);pool=h.table;apool=pool+0x1000;owner=pool+0x2000;vtable=owner+0x100;allocation=owner+0x200;free_at=0x3000800
    original=[];native=[];iteration=0
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,args):
        events.append((kind,args,bytes(read(0x4d8eb0,0x70)),bytes(read(pool,0x1800))))
        if iteration%3==0:
            if kind=='close':write(0x4d8ef4,pack(0x80020001 if iteration%2 else 0x12340001))
            if kind=='async':write(0x4d8f18,pack(allocation));write(0x4d8ef0,pack(0x11223344))
            if kind=='free':
                write(0x4d8f18,pack(allocation+4));write(0x4d8f14,pack(123));write(0x4d8f10,pack(owner+4))
        if kind=='continue':return 0x1500f2
        if kind=='status':return 0x1510f0
        return 0 if iteration%2 else 0x80004005
    cb={k:Call(lambda ctx,value,k=k:event(h.read,nw,native,k,(value,))) for k in ['status','continue','prepare','close','kind33','async']}
    online=CancelOps()
    for field,k in [('login_status','status'),('continue_task','continue'),('prepare_cancel','prepare'),('close_task','close'),('cancel_kind33','kind33')]:setattr(online,field,cb[k])
    asyncops=Ops(None,cb['async']);free=FreeFn(lambda ctx,obj,ptr:event(h.read,nw,native,'free',(obj,ptr)));allocator=Allocator(None,AllocFn(),free)
    addresses={0x3a0650:'status',0x3a0620:'continue',0x3a07b9:'prepare',0x3a062b:'close',0x3a6969:'kind33',0x3cd172:'async',free_at:'free'}
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);value=struct.unpack('<I',u.mem_read(esp+4,4))[0];kind=addresses[at]
        args=(u.reg_read(X.UC_X86_REG_ECX),value) if kind=='free' else (value,)
        result=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for at in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    cancel=h.lib.h2_discovery_cancel_tasks;cancel.argtypes=[C.POINTER(Memory),C.POINTER(CancelOps),C.POINTER(Ops)];cancel.restype=None
    stop=h.lib.h2_discovery_stop;stop.argtypes=cancel.argtypes+[C.POINTER(Allocator)];stop.restype=None
    for wrapper in [False,True]:
        for iteration in range(384):
            original.clear();native.clear();h.write(pool,rng.randbytes(0x2400))
            kind=[0,2,3,33,99][iteration%5]
            for a,stride in [(pool,20),(apool,12)]:
                entries=a+0x400;bitmap=a+0x300
                for off,v in [(0x20,3),(0x24,stride),(0x34,3),(0x38,3),(0x3c,3),(0x44,entries),(0x48,bitmap)]:h.write(a+off,pack(v))
                h.write(a+0x2a,bytes([8 if iteration%2 else 0]));h.write(bitmap,pack(7))
                for i in range(3):
                    entry=struct.pack('<HHIIII',0x8001+i,0,kind,0,0x1234,1) if stride==20 else struct.pack('<HHII',0x8001+i,0,allocation,0)
                    h.write(entries+i*stride,entry)
            h.write(0x4cf78c,pack(pool));h.write(0x4cf8d8,pack(apool));h.write(0x4cf8d4,bytes([0 if iteration%11==0 else 255]))
            h.write(0x467214,struct.pack('<II',0x80010000,77));h.write(0x4d8b18,b'\x01\x01')
            h.write(owner,pack(vtable));h.write(vtable+4,pack(free_at));h.write(0x4d8eb0,rng.randbytes(0x70))
            handles=[0xffffffff,0x12340001,0x80020001,0x80020003]
            h.write(0x4d8ef0,pack(handles[iteration//4%4]));h.write(0x4d8ef4,pack(handles[iteration%4]))
            h.write(0x4d8f08,bytes([iteration//16%2]));h.write(0x4d8eb4,bytes([0 if iteration%7==0 else 255]))
            h.write(0x4d8f10,pack(owner));h.write(0x4d8f18,pack(allocation if iteration//8%2 else 0))
            if wrapper:h.call('discovery_stop',0xb3670,{},[],lambda:stop(h.memory,C.byref(online),C.byref(asyncops),C.byref(allocator)))
            else:h.call('discovery_cancel_tasks',0xb31b0,{},[],lambda:cancel(h.memory,C.byref(online),C.byref(asyncops)))
            assert original==native,(wrapper,iteration)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/discovery-stop-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/discovery.c','include/halo2/discovery.h','src/online_tasks.c','src/async_tasks.c','src/data_array.c','tests/discovery_stop_oracle.py','tests/online_cancel_oracle.py','tests/async_tasks_oracle.py','tests/allocator_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original discovery cancellation/stop and online/async cancellation callees intact. SDK task and virtual allocator-release boundaries controlled. Full memory and callback snapshots; invalid/missing handles, task kinds, SDK errors, poisoned deletion, callback changes to later task/allocation, local/online mode and post-release global writes. No full networking shutdown or Linux SDK backend.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
