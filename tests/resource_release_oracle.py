#!/usr/bin/env python3
"""Pool/list release and tracked cleanup; actual engine callees, controlled SDK/callbacks."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STOP
from data_array_oracle import ROOT,Memory,EXPECTED
from network_task_complete_oracle import Invoke,Callbacks
from online_cancel_oracle import CancelOps
from online_poll_oracle import Call
Protect=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
Release=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32)
class Resources(C.Structure):
    _fields_=[('context',C.c_void_p),('protect',Protect),('release_entry',Release)]

def suite(h):
    rng=random.Random(0x12d520);a=h.table;manager=a;other=a+0x100;pool=a+0x200;altpool=a+0x300
    entries=a+0x400;altentries=a+0x500;resourcepool=a+0x700;resourceentries=a+0x800
    payload=a+0xa24;next_=a+0xb00;prev=a+0xb80;onlinepool=a+0x1000;onlineentries=a+0x1100
    obj=a+0x1400;otherobj=a+0x1500;table=a+0x1600
    original=[];native=[];iteration=0;mode='';coverage={}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    word=lambda v:struct.pack('<H',v&0xffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,*args):
        if events is original:
            key=mode+':'+kind;coverage[key]=coverage.get(key,0)+1
        events.append((kind,args,bytes(read(a,0x2000)),bytes(read(0x4d8ba0,0x310)),bytes(read(0x4e6454,0x14))))
        if iteration%3==0:
            if kind=='protect':
                # Entry pointer was captured before the SDK call, globals after it are fresh.
                write(0x4e6454,pack(altpool));write(0x4e6464,pack(other));write(payload-0x24,pack(0x80030002))
                write(payload-8,pack(prev));write(payload-4,pack(next_))
            elif kind=='release':
                # Both managers switch pool; already-captured list node remains in old pool.
                write(manager+0x64,pack(altpool));write(other+0x64,pack(pool))
                write(entries+24+12,pack(0xffffffff));write(entries+24+16,pack(0xffffffff))
            elif kind=='close':
                write(0x4d8c28+(iteration%32)*20,pack(otherobj))
            elif kind=='task':
                object=args[1];write(object+4,word(0xa55a));write(object+6,word(2))
                write(object+12,word(0));write(0x4d8c28+(iteration%32)*20,pack(otherobj))
        if kind=='continue':return 0x1500f2
        if kind=='prepare':return 0x80004005
        if kind=='task':return iteration%2
        return 0
    protect=Protect(lambda ctx,p,n,f:event(h.read,nw,native,'protect',p,n,f))
    release=Release(lambda ctx,fn,v:event(h.read,nw,native,'release',fn,v));resources=Resources(None,protect,release)
    invoke=Invoke(lambda ctx,fn,o:event(h.read,nw,native,'task',fn,o));tasks=Callbacks(None,invoke)
    online=CancelOps();refs={}
    for field,kind in [('login_status','status'),('continue_task','continue'),('prepare_cancel','prepare'),('close_task','close'),('cancel_kind33','kind33')]:
        refs[field]=Call(lambda ctx,v,kind=kind:event(h.read,nw,native,kind,v));setattr(online,field,refs[field])
    sdk={0x3a0650:'status',0x3a0620:'continue',0x3a07b9:'prepare',0x3a062b:'close',0x3a6969:'kind33'}
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);first=u32(u.mem_read,sp+4);argc=1
        if at==STOP+0x900:
            kind='protect';args=(first,u32(u.mem_read,sp+8),u32(u.mem_read,sp+12));argc=3
        elif at==STOP+0xa00:kind='release';args=(at,first)
        elif at==STOP+0xb00:kind='task';args=(at,first)
        else:kind=sdk[at];args=(first,)
        value=event(u.mem_read,u.mem_write,original,kind,*args)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+argc*4)
    for at in list(sdk)+[STOP+0x900,STOP+0xa00,STOP+0xb00]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    h.write(0x411568,pack(STOP+0x900))
    protectfn=h.lib.h2_memory_set_protection;protectfn.argtypes=[C.POINTER(Resources)]+[C.c_uint32]*3;protectfn.restype=None
    delete=h.lib.h2_resource_entry_delete;delete.argtypes=[C.POINTER(Memory),C.POINTER(Resources)]+[C.c_uint32]*2;delete.restype=None
    free=h.lib.h2_resource_buffer_release;free.argtypes=[C.POINTER(Memory),C.POINTER(Resources),C.c_uint32];free.restype=None
    remove=h.lib.h2_network_tracking_remove;remove.argtypes=[C.POINTER(Memory),C.POINTER(Callbacks),C.POINTER(CancelOps),C.POINTER(Resources)]+[C.c_uint32]*2;remove.restype=None
    for mode in ['protection','entry_delete','buffer_release','tracking_remove']:
        for iteration in range(512):
            original.clear();native.clear();h.write(a,rng.randbytes(0x2000));h.write(0x4d8ba0,rng.randbytes(0x310))
            for ar,el,bm,stride in [(pool,entries,a+0x600,24),(altpool,altentries,a+0x604,24),(resourcepool,resourceentries,a+0x608,40),(onlinepool,onlineentries,a+0x1200,20)]:
                for off,value in [(0x20,3),(0x24,stride),(0x34,3),(0x38,3),(0x3c,3),(0x44,el),(0x48,bm)]:h.write(ar+off,pack(value))
                h.write(ar+0x2a,bytes([8 if iteration%2 else 0]));h.write(bm,pack(7))
                for i in range(3):h.write(el+i*stride,word(0x8001+i))
            for man,ar in [(manager,pool),(other,altpool)]:
                h.write(man+0x64,pack(ar));h.write(man+0x20,pack(STOP+0xa00 if iteration%4 else 0))
            for el in [entries,altentries]:
                for i in range(3):
                    h.write(el+i*24+12,pack(0x80030002 if iteration&1 else 0xffffffff))
                    h.write(el+i*24+16,pack(0x80010000 if iteration&2 else 0xffffffff))
            h.write(0x4e6454,pack(resourcepool));h.write(0x4e6464,pack(manager));h.write(0x4e645c,pack(payload-0x24))
            length=[0,1,4096,0xffffffff][iteration%4]
            h.write(payload-0x24,pack(0x80020001));h.write(payload-0x1c,pack(a+0x1800));h.write(payload-0x18,pack(length))
            h.write(payload-8,pack(prev if iteration&4 else 0));h.write(payload-4,pack(next_ if iteration&8 else 0))
            h.write(0x4cf78c,pack(onlinepool));h.write(0x4d8b18,b'\1\1');h.write(0x467214,pack(0xffffffff))
            h.write(onlineentries+20,struct.pack('<HHIIII',0x8002,0,2,0,0x1234 if iteration%2 else 0,1))
            for object in [obj,otherobj]:
                h.write(object,pack(table if iteration%5 else 0));h.write(object+4,struct.pack('<HHHH',rng.getrandbits(16),[0,1,2,3][iteration%4],[0,1,2,4][iteration//4%4],[0,1,2][iteration//16%3]))
                h.write(object+0x24,pack(0 if iteration%7==0 and (iteration//4%4) in [0,3] else payload));h.write(object+0x28,pack(16))
            for off in [0x10,0x14,0x18]:h.write(table+off,pack(STOP+0xb00))
            for i in range(32):h.write(0x4d8c28+i*20,pack(0 if i%3 else obj))
            index=iteration%32
            h.write(0x4d8c28+index*20,struct.pack('<II',obj if iteration%9 else 0,0x80020001 if iteration%3 else 0xffffffff))
            for base in [0x4d8ba8,0x4d8be8]:
                for i in range(16):h.write(base+i*4,pack([0xffffffff,index,(i+1)%32][(i+iteration)%3]))
            h.write(0x55e700,pack(0xffffffff if iteration%2 else 0))
            reason=[0,1,6,7,13][iteration//8%5]
            try:
                if mode=='protection':h.call(mode,0x2d15da,{},[a+0x1800,length,0x404],lambda:protectfn(C.byref(resources),a+0x1800,length,0x404))
                elif mode=='entry_delete':h.call(mode,0x13d830,dict(edi=manager,ebx=0x80020001),[],lambda:delete(h.memory,C.byref(resources),manager,0x80020001))
                elif mode=='buffer_release':h.call(mode,0x12d520,dict(esi=payload),[],lambda:free(h.memory,C.byref(resources),payload))
                else:h.call(mode,0x8e0f0,{},[index,reason],lambda:remove(h.memory,C.byref(tasks),C.byref(online),C.byref(resources),index,reason))
            except Exception:
                print('mode',mode,'iteration',iteration,'EIP',hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
            assert original==native,(mode,iteration)
    for key in ['tracking_remove:protect','tracking_remove:release','tracking_remove:task','tracking_remove:close','entry_delete:release','buffer_release:protect']:
        assert coverage.get(key,0)>0,(key,coverage)
    h.release_coverage=coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/resource-release-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/resource_release.c','include/halo2/resource_release.h','src/network_tracking.c','include/halo2/network_tracking.h','src/online_tasks.c','src/data_array.c','src/crc.c','tests/resource_release_oracle.py','tests/network_task_complete_oracle.py','tests/online_cancel_oracle.py','tests/online_poll_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,boundary_coverage=h.release_coverage,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Protection wrapper, pool entry unlink/deletion, resource buffer release and tracked-task removal. Actual scheduling, CRC, cancellation and data-array deletion callees. SDK protection/online operations and object/release callbacks controlled. Full memory and event comparisons, poison flags, list endpoints, callback replacement of pools/managers/tracked objects, zero lengths, missing records, task retries. No Linux protection/online backend or complete network shutdown.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
