#!/usr/bin/env python3
"""Task creation against original instructions and actual data-pool allocation."""
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

Create = C.CFUNCTYPE(C.c_uint32, C.c_void_p, *([C.c_uint32]*12))
class Platform(C.Structure):
    _fields_ = [('context', C.c_void_p), ('create', Create),
                ('tasks', C.POINTER(Ops)), ('scratch', C.c_uint32)]

def suite(h):
    rng = random.Random(0x7b4c0)
    pool = h.table
    other = pool + 0x100
    records = pool + 0x1000
    scratch = pool + 0x3000
    stack_scratch = STACK + 0x8000 - 0x304
    original, native = [], []
    fn = h.lib.h2_async_task_create
    fn.argtypes = [C.POINTER(Memory), C.POINTER(Platform)] + [C.c_uint32]*4
    fn.restype = C.c_uint32
    def native_write(address, data):
        C.memmove(h.pointer + address - BASE, data, len(data))
    def create(read, write, events, args):
        count, a, b, c, z1, z2, z3, value, option, z4, z5, output = args
        n = 0 if count & 0x80000000 else count
        assert [z1,z2,z3,z4,z5] == [0]*5
        assert (a-output,b-output,c-output) == (0x204,0x104,4)
        arrays = tuple(bytes(read(addr,n*4)) for addr in [a,b,c])
        events.append(('create', count, value, option, arrays, bytes(read(pool,0x800))))
        write(output, struct.pack('<I', task))
        if mutate:
            write(0x4cf8d8, struct.pack('<I',other))
            write(0x440188, b'\xab'*16)
            write(records, b'\xcd'*60)
        return error
    def release(read, write, events, value):
        events.append(('release', value, bytes(read(pool,0x800))))
        write(records+60, b'\xef'*4)
        return 0x80004005
    create_cb = Create(lambda ctx,*args:create(h.read,native_write,native,args))
    release_cb = Call(lambda ctx,value:release(h.read,native_write,native,value))
    tasks = Ops(None,release_cb)
    ops = Platform(None,create_cb,C.pointer(tasks),scratch)
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        nargs=12 if address==0x3cd156 else 1
        args=struct.unpack('<'+'I'*nargs,u.mem_read(esp+4,nargs*4))
        if nargs==12: result=create(u.mem_read,u.mem_write,original,args)
        else: result=release(u.mem_read,u.mem_write,original,args[0])
        u.reg_write(X.UC_X86_REG_EAX,result)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+4+nargs*4)
    for address in [0x3cd156,0x3cd172]:
        h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    for case in range(512):
        h.write(pool,rng.randbytes(0x4000))
        enabled=0 if case%17==0 else rng.choice([1,255])
        mutate=bool(case%2)
        error=[0,0,0,1,0x80004005][case%5]
        task=rng.getrandbits(32)
        for j,p in enumerate([pool,other]):
            entries=pool+0x400+j*0x100
            bitmap=pool+0x300+j*4
            used=[0,1,3,7,15,31,0b10101][(case+j)%7]
            stride=rng.choice([8,12,16])
            high=used.bit_length()
            for off,value in [(0x20,5),(0x24,stride),(0x34,0),(0x38,high),
                              (0x3c,used.bit_count()),(0x44,entries),(0x48,bitmap)]:
                h.write(p+off,struct.pack('<I',value))
            h.write(p+0x40,struct.pack('<H',rng.choice([0x8000,0xfffe,0x1234])))
            h.write(bitmap,struct.pack('<I',used))
            for i in range(5):
                h.write(entries+i*stride,struct.pack('<H',0x8001 if used>>i&1 else 0))
        h.write(0x4cf8d4,bytes([enabled]))
        h.write(0x4cf8d8,struct.pack('<I',pool))
        h.write(0x440188,rng.randbytes(16))
        kind=case%2
        count=[0,1,2,63,64,65,0x7fffffff,0xffffffff,0x80000000][case%9]
        option=0xffffffff if case%3 else rng.getrandbits(32)
        seed=rng.randbytes(0x304)
        h.write(scratch,seed)
        h.u.mem_write(stack_scratch,seed)
        original.clear();native.clear()
        def run():
            result=fn(h.memory,C.byref(ops),kind,count,option,records)
            assert h.read(scratch,0x304)==bytes(h.u.mem_read(stack_scratch,0x304)),case
            native_write(scratch,seed)
            return result
        h.call('create',0x7b4c0,dict(ecx=kind,edx=count,eax=option),[records],run,mask=0xffffffff)
        assert original==native,(case,original,native)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/async-task-create-tests.json')
    args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try: suite(h)
    finally: h.close()
    sources=['src/async_task_create.c','include/halo2/async_task_create.h',
             'src/data_array.c','tests/async_task_create_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,
        library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),
        source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original task creation and data allocation. SDK create/release controlled; callback arrays, argument order, snapshots, signed clamp, option defaults, pool replacement, allocation exhaustion and cleanup. Full guest memory and normalized scratch compared. SDK task execution not recovered.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__': main()
