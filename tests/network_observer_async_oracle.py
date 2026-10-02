#!/usr/bin/env python3
"""Observer task lifecycle with actual task creation/result/release routines."""
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE, STACK
from data_array_oracle import ROOT, Memory, EXPECTED
from async_tasks_oracle import Ops, Call
from async_task_create_oracle import Platform, Create

def suite(h):
    rng=random.Random(0x77480)
    observer=h.table;pool=observer+0x6000;other=pool+0x100
    task=pool+0x900;records=pool+0x1000;scratch=pool+0x1100
    original=[];native=[];coverage={'create':0,'release':0,'decoded':0,'completed-on-next-poll':0}
    fn=h.lib.h2_network_observer_async
    fn.argtypes=[C.POINTER(Memory),C.POINTER(Platform)]+[C.c_uint32]*3
    fn.restype=None
    def write(address,data):C.memmove(h.pointer+address-BASE,data,len(data))
    def create(read,put,events,args):
        count,a,b,c,z1,z2,z3,value,option,z4,z5,out=args
        assert count==1 and [z1,z2,z3,z4,z5]==[0]*5
        ptrs=[struct.unpack('<I',read(p,4))[0] for p in [a,b,c]]
        assert ptrs[0]==ptrs[1]+24 and ptrs[2]==ptrs[1]+8
        events.append(('create',value,option,bytes(read(ptrs[1],60)),bytes(read(entry,0xa0))))
        put(out,struct.pack('<I',task))
        if mutate:
            put(0x4cf8d8,struct.pack('<I',other))
            put(entry+0x14,b'\xa7'*36)
            put(entry+0x70,struct.pack('<I',0xdeadbeef))
        return error
    def release(read,put,events,value):
        events.append(('release',value,bytes(read(entry,0xa0)),bytes(read(pool,0x800))))
        if mutate:
            put(entry+8,b'\xa1')
            put(entry+0x70,struct.pack('<I',0xdeadbeef))
            put(0x4cf8d8,struct.pack('<I',other))
        return release_error
    cb=Create(lambda ctx,*args:create(h.read,write,native,args))
    rb=Call(lambda ctx,value:release(h.read,write,native,value))
    tasks=Ops(None,rb);ops=Platform(None,cb,C.pointer(tasks),scratch)
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);n=12 if address==0x3cd156 else 1
        args=struct.unpack('<'+'I'*n,u.mem_read(esp+4,4*n))
        result=create(u.mem_read,u.mem_write,original,args) if n==12 else release(u.mem_read,u.mem_write,original,args[0])
        u.reg_write(X.UC_X86_REG_EAX,result)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+4+4*n)
    for a in [0x3cd156,0x3cd172]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=a,end=a)
    for case in range(1024):
        h.write(observer,rng.randbytes(0x7404))
        index=case%15;entry=observer+0xa8+index*0x528
        mode=case%8;mutate=bool(case%3);error=0 if case%5 else 0x80004005
        release_error=0 if case%3 else 0x80004005
        h.write(0x4cf8d4,bytes([0 if mode==7 else 1]))
        h.write(0x4cf8d8,struct.pack('<I',pool))
        h.write(0x440188,rng.randbytes(16))
        for j,p in enumerate([pool,other]):
            entries=pool+0x400+j*0x100;bitmap=pool+0x300+j*4
            used=15 if mode==6 else 1
            for off,value in [(0x20,4),(0x24,8),(0x34,0),(0x38,used.bit_length()),
                              (0x3c,used.bit_count()),(0x44,entries),(0x48,bitmap)]:
                h.write(p+off,struct.pack('<I',value))
            h.write(p+0x40,struct.pack('<H',0x8002));h.write(p+0x2a,bytes([8 if case%2 else 0]))
            h.write(bitmap,struct.pack('<I',used))
            for slot in range(4):h.write(entries+slot*8,struct.pack('<HHI',0x8001 if used>>slot&1 else 0,1,task))
        h.write(task+4,struct.pack('<I',1 if mode in [0,2] else 0))
        h.write(task+8,bytes([rng.choice([0,2,3,0x12,0x1b,0xff])]))
        h.write(entry,struct.pack('<I',0 if mode==4 else 2))
        h.write(entry+8,bytes([8 if mode==5 else 0, rng.randrange(256)]))
        existing=0x80010000 if mode in [1,2,3,4,7] else 0xffffffff
        if mode==3:existing=0x80030000
        h.write(entry+0x70,struct.pack('<I',existing))
        for i in range(4):h.write(observer+0x18+i*36,struct.pack('<I',0xffffffff if rng.randrange(3)==0 else i))
        original.clear();native.clear()
        seed=h.read(records,0x404)
        record_seed=seed[:60];h.u.mem_write(STACK+0x8000-60,record_seed)
        def run():
            fn(h.memory,C.byref(ops),observer,index,records)
            assert h.read(records,60)==bytes(h.u.mem_read(STACK+0x8000-60,60)),case
            write(records,seed)
        h.call('observer-async',0x77480,dict(eax=index,edx=observer),[],run)
        assert original==native,(case,original,native)
        for event in original:coverage[event[0]]+=1
        if h.read(entry+8,1)[0]&0x10:coverage['decoded']+=1
        if mode==0 and h.u32(entry+0x70)!=0xffffffff:
            # Complete a task created by the preceding call, then poll again.
            h.write(task+4,struct.pack('<I',0));h.write(task+8,b'\x1b')
            original.clear();native.clear()
            h.u.mem_write(STACK+0x8000-60,record_seed)
            h.call('complete-created-task',0x77480,dict(eax=index,edx=observer),[],run)
            assert original==native,(case,original,native)
            assert h.u32(entry+0x70)==0xffffffff
            assert [event[0] for event in original]==['release']
            coverage['completed-on-next-poll']+=1
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/network-observer-async-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try: coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_async.c','include/halo2/network_observer_async.h',
             'src/async_task_create.c','src/async_task_result.c','src/async_tasks.c','src/data_array.c',
             'tests/network_observer_async_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),coverage=coverage,
        source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original observer, task create/idle/result/release and data allocation/deletion instructions. SDK create/release controlled. Full memory, normalized temporary records, callback arguments/snapshots, consumer selection, pending/invalid/completed tasks, disabled subsystem, SDK errors, exhausted pools and callback mutations. No live SDK task service.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
