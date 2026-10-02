#!/usr/bin/env python3
"""Original/native transport initialization, controlled allocation and network boundaries."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from data_array_oracle import ROOT,Memory,EXPECTED
from allocator_oracle import Allocator
from hash_crc_oracle import Harness
from game_lifecycle_oracle import Operations as LifecycleOps,FP,Dispatch
from arena_oracle import Platform
Query=C.CFUNCTYPE(C.c_uint32,C.c_void_p)
Start=C.CFUNCTYPE(None,C.c_void_p)
class Operations(C.Structure):
    _fields_=[('context',C.c_void_p),('query_link',Query),('start_online',Start)]
def suite(h):
    lib=h.lib;rng=random.Random(690);original=[];native=[];link=0
    def snapshot(read):return (bytes(read(0x4d8b18,0x88)),bytes(read(0x4cf790,0x14c)),bytes(read(0x55e704,4)))
    def query(ctx):native.append(('query',snapshot(h.read)));return link
    def start(ctx):native.append(('start',snapshot(h.read)))
    ops=Operations(None,Query(query),Start(start))
    def boundary(u,address,size,ctx):
        original.append(('query' if address==0x36c47d else 'start',snapshot(u.mem_read)))
        if address==0x36c47d:u.reg_write(X.UC_X86_REG_EAX,link)
        esp=u.reg_read(X.UC_X86_REG_ESP)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    for address in [0x36c47d,0x8d840]:h.u.hook_add(U.UC_HOOK_CODE,boundary,begin=address,end=address)
    lib.h2_transport_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Allocator),C.POINTER(Operations)];lib.h2_transport_initialize.restype=None
    lib.h2_transport_qos_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Allocator)];lib.h2_transport_qos_initialize.restype=None
    lib.h2_transport_address_initialize.argtypes=[C.POINTER(Memory)];lib.h2_transport_address_initialize.restype=None
    lib.h2_transport_register.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4;lib.h2_transport_register.restype=None
    lib.h2_transport_is_active.argtypes=[C.POINTER(Memory)];lib.h2_transport_is_active.restype=C.c_uint32
    h.write(0x468758,struct.pack('<I',h.identity))
    for failure in [False,True]:
        for link in [0,1,2,3,0x80000000,0xffffffff]:
            for cache in [link,link^0xffffffff]:
                h.write(0x4d8b18,rng.randbytes(0x88));h.write(0x4cf790,rng.randbytes(0x14c));h.write(h.table,b'\xa5'*0x200)
                h.write(0x55e704,struct.pack('<I',cache));h.allocation=0 if failure else h.table
                original.clear();native.clear()
                h.call('initialize',0x8d690,{},[],lambda:lib.h2_transport_initialize(h.memory,C.byref(h.allocator),C.byref(ops)))
                assert original==native,(original,native)
                assert [x[0] for x in native]==(['query','start'] if link&1 else ['query'])
                assert h.u32(0x4d8b1c)==1 and h.u32(0x4cf8d8)==h.allocation
        h.call('qos_initialize',0x7b3e0,{},[],lambda:lib.h2_transport_qos_initialize(h.memory,C.byref(h.allocator)))
    # Execute the first actual startup subsystem, with other subsystem bodies
    # controlled. This connects recovered orchestration and transport natively.
    lib.h2_game_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Platform),C.POINTER(LifecycleOps)]
    lib.h2_game_initialize.restype=None
    native_dispatch=[];original_dispatch=[]
    def dispatch(ctx,function):
        native_dispatch.append(function)
        if function==0x8d690:lib.h2_transport_initialize(h.memory,C.byref(h.allocator),C.byref(ops))
    lifecycle=LifecycleOps(None,FP(lambda ctx,value,mask:None),Dispatch(dispatch),Dispatch(lambda ctx,p:None))
    platform=Platform()
    targets={h.u32(0x440dd8+i*36) for i in range(68)}
    def lifecycle_hook(u,address,size,ctx):
        if address not in targets and address!=0x3212d6:return
        esp=u.reg_read(X.UC_X86_REG_ESP);ret=struct.unpack('<I',u.mem_read(esp,4))[0]
        if address in targets:
            if ret!=0x137c8c:return
            original_dispatch.append(address)
            if address==0x8d690:return
        u.reg_write(X.UC_X86_REG_EIP,ret);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    handle=h.u.hook_add(U.UC_HOOK_CODE,lifecycle_hook)
    for failure in [False,True]:
        for link in [0,1]:
            h.write(0x4e3b60,b'\1');h.write(0x4e6080,struct.pack('<IIII',h.table+0x3000,0,0,0xffffffff))
            h.allocation=0 if failure else h.table
            original.clear();native.clear();original_dispatch.clear();native_dispatch.clear()
            h.call('integrated_game_initialize',0x137c20,{},[],lambda:lib.h2_game_initialize(h.memory,C.byref(platform),C.byref(lifecycle)))
            assert original==native and original_dispatch==native_dispatch
            assert len(original_dispatch)==68 and original_dispatch[0]==0x8d690
    h.u.hook_del(handle)
    for index in range(8):
        h.write(0x4d8b18,rng.randbytes(0x88));h.write(0x4d8b1c,struct.pack('<I',index))
        values=[rng.getrandbits(32) for _ in range(4)]
        h.call('register',0x8d770,dict(ecx=values[0]),values[1:],lambda:lib.h2_transport_register(h.memory,*values))
        h.write(0x4d8b1c,struct.pack('<I',index));h.write(0x4cf790,rng.randbytes(0x144))
        h.call('address_initialize',0x7a840,{},[],lambda:lib.h2_transport_address_initialize(h.memory))
    for initialized in [0,1,2,127,128,255]:
        for active in [0,1,2,127,128,255]:
            h.write(0x4d8b18,bytes([initialized,active]))
            result=h.call('is_active',0x8d7c0,{},[],lambda:lib.h2_transport_is_active(h.memory),0xffffffff)
            assert result==int(bool(initialized and active))
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/transport-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/transport.c','tests/transport_oracle.py','tests/hash_crc_oracle.py']},scope='Five routines. Allocator, link query, and online startup are controlled boundaries. Does not implement network connectivity.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
