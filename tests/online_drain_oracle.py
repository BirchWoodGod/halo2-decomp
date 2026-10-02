#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STOP
from online_cancel_oracle import CancelOps
from online_poll_oracle import Call
from async_tasks_oracle import Ops as AsyncOps
Query=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32)
Release=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class BufferOps(C.Structure):
    _fields_=[("context",C.c_void_p),("query",Query),("release",Release)]
from allocator_oracle import Allocator,AllocFn,FreeFn
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    lib=h.lib;rng=random.Random(0x6b950);a=h.table;b=a+0x1000;free=STOP+0x200
    original=[];native=[];switch=False;replace_on_free=False;mutate_runtime=False
    def nw(p,data):C.memmove(h.pointer+p-BASE,data,len(data))
    def event(read,write,events,kind,args):
        events.append((kind,args,bytes(read(a,0x4c)),bytes(read(b,0x4c)),bytes(read(0x4cf78c,4)),bytes(read(0x477088,0xc0))))
        if switch and kind=='close' and sum(e[0]=='close' for e in events)==1:write(0x4cf78c,struct.pack('<I',b))
        if mutate_runtime and kind=='close' and len(events)==1:
            write(0x477140,struct.pack('<I',0x81030003))
        if kind=='release':
            assert bytes(read(args[1],0x4c))==bytes(0x4c)
            if replace_on_free:write(0x4cf78c,struct.pack('<I',b));write(0x479748,struct.pack('<I',0x81000000))
        return 0x1510f0 if kind=='status' else 0x1500f2 if kind=='continue' else 0
    callbacks={name:Call(lambda ctx,handle,name=name:event(h.read,nw,native,name,(handle,))) for name in ['status','continue','prepare','close','kind33']}
    ops=CancelOps()
    for field,name in [('login_status','status'),('continue_task','continue'),('prepare_cancel','prepare'),('close_task','close'),('cancel_kind33','kind33')]:setattr(ops,field,callbacks[name])
    allocation=AllocFn(lambda ctx,identity,size:0)
    release=FreeFn(lambda ctx,identity,address:event(h.read,nw,native,'release',(identity,address)))
    allocator=Allocator(None,allocation,release)
    addresses={0x3a0650:'status',0x3a0620:'continue',0x3a07b9:'prepare',0x3a062b:'close',0x3a6969:'kind33',free:'release'}
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);value=struct.unpack('<I',u.mem_read(esp+4,4))[0]
        args=(u.reg_read(X.UC_X86_REG_ECX),value) if address==free else (value,)
        result=event(u.mem_read,u.mem_write,original,addresses[address],args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for address in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    h.write(h.vtable+4,struct.pack('<I',free))
    lib.h2_online_tasks_drain.argtypes=[C.POINTER(Memory),C.POINTER(CancelOps)];lib.h2_online_tasks_drain.restype=None
    lib.h2_online_tasks_dispose.argtypes=[C.POINTER(Memory),C.POINTER(Allocator),C.POINTER(CancelOps)];lib.h2_online_tasks_dispose.restype=None
    def setup(kinds,poison=False,identity=True):
        for array in [a,b]:
            h.write(array,rng.randbytes(0x800));entries=array+0x100;bitmap=array+0x80
            for off,value in [(0x20,24),(0x24,20),(0x30,h.identity if identity else 0),(0x34,len(kinds)),(0x38,len(kinds)),(0x3c,len(kinds)),(0x44,entries),(0x48,bitmap)]:h.write(array+off,struct.pack('<I',value))
            h.write(array+0x2a,bytes([8 if poison else 0]));h.write(bitmap,struct.pack('<I',(1<<len(kinds))-1))
            for i,kind in enumerate(kinds):h.write(entries+i*20,struct.pack('<HHIIII',0x8100+i,0,kind,0,0x1000+i,1))
        h.write(0x4cf78c,struct.pack('<I',a));h.write(0x4d8b18,b'\1\1')
        login=((0x8100+kinds.index(1))<<16)|kinds.index(1) if 1 in kinds else 0xffffffff
        h.write(0x467214,struct.pack('<II',login,1));h.write(0x479748,struct.pack('<I',0xffffffff))
        original.clear();native.clear()
    for iteration in range(48):
        kinds=[0,1,2,33,11,12,3,99];rng.shuffle(kinds)
        if iteration==0:kinds=[]
        switch=bool(iteration%2);replace_on_free=False
        setup(kinds,iteration%3==0)
        h.call('drain',0x6b950,{},[],lambda:lib.h2_online_tasks_drain(h.memory,C.byref(ops)))
        assert original==native
        assert h.u32(h.u32(0x4cf78c)+0x3c)==0
    for iteration in range(24):
        switch=False;replace_on_free=bool(iteration%2);identity=iteration%3!=0
        setup([0,1,2,33,11,12,3,99],iteration%4==0,identity)
        h.write(0x479748,struct.pack('<I',0x81000000 if iteration%2 else 0xffffffff))
        h.call('dispose',0x6b450,{},[],lambda:lib.h2_online_tasks_dispose(h.memory,C.byref(allocator),C.byref(ops)))
        assert original==native and h.read(a,0x4c)==bytes(0x4c)
        assert h.u32(0x479748)==0xffffffff
        assert sum(e[0]=='release' for e in native)==int(identity)
    lib.h2_network_parameter_runtime_dispose.argtypes=[C.POINTER(Memory),C.POINTER(CancelOps)]
    lib.h2_network_parameter_runtime_dispose.restype=None
    slots=[0x477098,0x4770a0,0x477138,0x477140]
    for variant in range(4):
        for mask in range(16):
            switch=False;replace_on_free=False;mutate_runtime=variant==3
            setup([99,99,99,99],bool(mask%2))
            h.write(0x477088,rng.randbytes(0xc0))
            for i,slot in enumerate(slots):
                handle=((0x8100+i)<<16)|i
                if variant==1:handle=0x81000000
                if variant==2:handle=0x12340000|i
                h.write(slot,struct.pack('<I',handle if mask&(1<<i) else 0xffffffff))
            h.call('parameter-runtime-dispose',0x72d30,{},[],lambda:lib.h2_network_parameter_runtime_dispose(h.memory,C.byref(ops)))
            assert original==native
            assert all(h.u32(slot)==0xffffffff for slot in slots)
            assert all(h.read(flag,1)==b'\0' for flag in [0x477088,0x477094,0x477134])
    operation=a+0x3000;wrapper=a+0x4000;other=wrapper+0x20;identity=wrapper+0x40;vtable=wrapper+0x60
    query_address=STOP+0x300;release_address=STOP+0x400
    buffer_original=[];buffer_native=[];mutation=0
    def buffer_event(read,write,events,kind,args):
        events.append((kind,args,bytes(read(operation,0xb0)),bytes(read(wrapper,0x40))))
        if kind=='release' and mutation==3:
            write(args[1],b'\xaa'*16)
            write(operation+0x10,struct.pack('<I',0xffffffff))
            write(wrapper+4,struct.pack('<I',0x12345678))
        if kind=='query' and mutation==1:write(0x4d87f8,struct.pack('<I',other))
        if kind=='release' and mutation==2:
            write(0x4d87f8,struct.pack('<I',other))
            write(operation+0x8c,struct.pack('<I',0x345678))
    query=Query(lambda ctx,ident,buf:buffer_event(h.read,nw,buffer_native,'query',(ident,buf)))
    buffer_release=Release(lambda ctx,ident,buf,flags:buffer_event(h.read,nw,buffer_native,'release',(ident,buf,flags)))
    buffer_ops=BufferOps(None,query,buffer_release)
    async_callback=Call(lambda ctx,handle:event(h.read,nw,native,'async',(handle,)))
    async_ops=AsyncOps(None,async_callback)
    def buffer_hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);buf,extra=struct.unpack('<II',u.mem_read(esp+4,8));ident=u.reg_read(X.UC_X86_REG_ECX)
        kind='query' if address==query_address else 'release'
        args=(ident,buf) if kind=='query' else (ident,buf,extra)
        buffer_event(u.mem_read,u.mem_write,buffer_original,kind,args)
        if kind=='query':u.mem_write(extra,struct.pack('<I',0x12345678))
        u.reg_write(X.UC_X86_REG_EAX,0);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+12)
    for address in [query_address,release_address]:h.u.hook_add(U.UC_HOOK_CODE,buffer_hook,begin=address,end=address)
    addresses[0x3cd172]='async';h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3cd172,end=0x3cd172)
    fn=lib.h2_network_parameter_operation_dispose
    fn.argtypes=[C.POINTER(Memory),C.POINTER(CancelOps),C.POINTER(AsyncOps),C.POINTER(BufferOps),C.c_uint32];fn.restype=None
    for mutation in range(3):
        for mask in range(64):
            switch=False;replace_on_free=False;mutate_runtime=False
            setup([99,99,99,99],bool(mask%2))
            # A distinct async pool uses the same validated record layout here.
            h.write(0x4cf8d4,b'\1');h.write(0x4cf8d8,struct.pack('<I',b))
            h.write(operation,rng.randbytes(0xb0));h.write(operation+8,struct.pack('<I',[0,1,2,0xffffffff][mask%4]))
            for i,off in enumerate([0x70,0x74,0x78]):h.write(operation+off,struct.pack('<I',((0x8100+i)<<16)|i if mask&(1<<i) else 0xffffffff))
            for i,off in enumerate([0x90,0x8c,0xa0]):h.write(operation+off,struct.pack('<I',0x123400+i if mask&(8<<i) else 0))
            h.write(wrapper,struct.pack('<II',identity,0));h.write(other,struct.pack('<II',identity,7));h.write(identity,struct.pack('<I',vtable));h.write(vtable,struct.pack('<II',release_address,query_address));h.write(0x4d87f8,struct.pack('<I',wrapper))
            buffer_original.clear();buffer_native.clear()
            h.call('parameter-operation-dispose',0x90c80,{},[operation],lambda:fn(h.memory,C.byref(ops),C.byref(async_ops),C.byref(buffer_ops),operation))
            assert original==native and buffer_original==buffer_native
            assert h.read(operation,1)==b'\0'
    remove=lib.h2_network_parameter_request_remove
    remove.argtypes=[C.POINTER(Memory),C.POINTER(BufferOps),C.c_uint32,C.c_uint32];remove.restype=None
    for mutation in range(4):
        for count in range(6):
            nodes=[operation+0x200+i*0x40 for i in range(count)]
            for target in nodes+[operation+0x600]:
                h.write(operation,rng.randbytes(0x800))
                h.write(operation+0xc,struct.pack('<II',nodes[0] if nodes else 0,count))
                for i,node in enumerate(nodes):h.write(node,struct.pack('<I',nodes[i+1] if i+1<count else 0))
                h.write(wrapper,struct.pack('<II',identity,0));h.write(other,struct.pack('<II',identity,7));h.write(identity,struct.pack('<I',vtable));h.write(vtable,struct.pack('<II',release_address,query_address));h.write(0x4d87f8,struct.pack('<I',wrapper))
                buffer_original.clear();buffer_native.clear()
                h.call('parameter-request-remove',0x6ddb0,dict(ebx=operation,esi=target),[],lambda:remove(h.memory,C.byref(buffer_ops),operation,target))
                assert buffer_original==buffer_native
                assert len(buffer_native)==(2 if target in nodes else 0)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/online-drain-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/async_tasks.c','include/halo2/async_tasks.h','tests/async_tasks_oracle.py','src/network_parameters.c','include/halo2/network_parameters.h','src/online_tasks.c','src/data_array.c','src/data_array_alloc.c','src/transport.c','tests/online_drain_oracle.py','tests/online_cancel_oracle.py','tests/online_poll_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Request unlink/release (84 cases, original list traversal and virtual buffer boundaries), operation cleanup (192 cases, original engine callees intact, SDK and buffer virtual methods controlled; query stack output discarded), drain, pool dispose and parameter runtime dispose (64 combinations including duplicate/invalid handles and callback mutation);  original engine callees intact. SDK and allocator release controlled. Full memory and callback snapshots, shuffled dependency order, pool replacement and release-time mutations. Not complete network shutdown.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
