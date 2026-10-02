#!/usr/bin/env python3
"""Online status/continuation against original code, SDK calls controlled."""
import argparse
import ctypes as C
import hashlib
import itertools
import json
import random
import struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
Call=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32)
class Operations(C.Structure):
    _fields_=[('context',C.c_void_p),('login_status',Call),('continue_task',Call)]

def suite(h):
    lib=h.lib;rng=random.Random(0x6cd50);array=h.table;login=array+0x400;task=login+20
    original=[];native=[];sdk_result=0;continuation=0;mutate=False
    def nw(a,data):C.memmove(h.pointer+a-BASE,data,len(data))
    def event(read,write,events,kind,handle):
        events.append((kind,handle,bytes(read(login,40)),bytes(read(0x467214,8)),bytes(read(0x50944f,1))))
        if mutate:
            write(login+2,b'\x81\x7f')
            write(task+0xc,struct.pack('<I',0x76543210))
        return sdk_result if kind=='status' else continuation
    ops=Operations(None,Call(lambda ctx,a:event(h.read,nw,native,'status',a)),
                   Call(lambda ctx,a:event(h.read,nw,native,'continue',a)))
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);handle=struct.unpack('<I',u.mem_read(esp+4,4))[0]
        value=event(u.mem_read,u.mem_write,original,'status' if address==0x3a0650 else 'continue',handle)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for address in [0x3a0650,0x3a0620]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    for name in ['login_status','task_continue']:
        fn=getattr(lib,'h2_online_'+name);fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];fn.restype=C.c_uint32
    def setup(active,kind,flags,sdk_handle,cached):
        h.write(array,rng.randbytes(0x500))
        h.write(0x4cf78c,struct.pack('<I',array))
        for offset,value in [(0x38,2),(0x24,20),(0x44,login)]:h.write(array+offset,struct.pack('<I',value))
        h.write(login,struct.pack('<HHIIII',0x8001,flags,kind,0,sdk_handle,cached))
        h.write(task,struct.pack('<HHIIII',0x8002,0,2,0,0x12345678,0))
        h.write(0x4d8b18,bytes(active));h.write(0x467214,struct.pack('<II',0x80010000,0xabcdef01))
        h.write(0x50944f,b'\xa5');original.clear();native.clear()
    results=[0,0x1510f0,0x1512f0,0x80151200,*range(0x80151000,0x80151008),0x7fffffff,0xffffffff]
    terminal={0x80151200:2,0x80151001:4,0x80151002:3,0x80151003:8,0x80151004:5,0x80151005:7,0x80151006:6}
    for sdk_result,active,mutate in itertools.product(results,[(0,0),(1,0),(0,1),(1,255)],[False,True]):
        setup(active,2,0x8101,0x1234,77)
        value=h.call('login_status',0x6cd50,dict(eax=0x80010000),[],
                     lambda:lib.h2_online_login_status(h.memory,C.byref(ops),0x80010000),0xffffffff)
        expected=5 if not all(active) else 0 if sdk_result==0 else 1 if sdk_result==0x1510f0 else terminal.get(sdk_result,10)
        assert value==expected and original==native
    for handle,kind,flags,sdk_handle in itertools.product([0xffffffff,0x12340000,0x80010000],[1,2],[0,0x20],[0,0xffffffff]):
        setup((1,1),kind,flags,sdk_handle,77)
        h.call('login_cached',0x6cd50,dict(eax=handle),[],
               lambda:lib.h2_online_login_status(h.memory,C.byref(ops),handle),0xffffffff)
        assert not original and not native
    for active,kind,login_handle,cached,mutate in itertools.product(
            [(0,1),(1,1)],[0,2],[0xffffffff,0x80010000],[0,1,5],[False,True]):
        sdk_result=0x1510f0;continuation=rng.getrandbits(32)
        setup(active,1,0,0x1234,cached)
        h.write(task+4,struct.pack('<I',kind));h.write(0x467214,struct.pack('<I',login_handle))
        value=h.call('continue_cached',0x6c670,dict(esi=task),[],
                     lambda:lib.h2_online_task_continue(h.memory,C.byref(ops),task),0xffffffff)
        allowed=(kind==0 and all(active)) or (login_handle!=0xffffffff and cached==1)
        assert value==(continuation if allowed else 0x80151000) and original==native
    for sdk_result,mutate in itertools.product(results,[False,True]):
        continuation=rng.getrandbits(32);setup((1,1),2,0,0x1234,77)
        h.call('continue_poll',0x6c670,dict(esi=task),[],
               lambda:lib.h2_online_task_continue(h.memory,C.byref(ops),task),0xffffffff)
        assert original==native
    for address,handle in [(0,0),(task,0),(task,0xffffffff)]:
        setup((1,1),2,0,0x1234,0);h.write(task+0xc,struct.pack('<I',handle))
        assert h.call('continue_invalid',0x6c670,dict(esi=address),[],
                      lambda:lib.h2_online_task_continue(h.memory,C.byref(ops),address),0xffffffff)==0x80004005
        assert not original and not native

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/online-poll-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/online_tasks.c','src/transport.c','tests/online_poll_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                comparisons=h.counts,total_comparisons=sum(h.counts.values()),
                source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                scope='Login status and task continuation, original lookup/transport/status callees intact; SDK calls controlled. Full memory, return bits and intermediate callback snapshots. No online service backend or cancellation completion.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
