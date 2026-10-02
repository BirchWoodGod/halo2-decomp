#!/usr/bin/env python3
"""Online-task startup, with only the allocation boundary controlled."""
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
import unicorn as U
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE, ALLOCATE
from allocator_oracle import Allocator, AllocFn, FreeFn
from data_array_oracle import ROOT, Memory, EXPECTED


def suite(h):
    lib = h.lib
    rng = random.Random(0x6b3e0)
    lib.h2_online_address_classify.argtypes = [C.POINTER(Memory)]
    lib.h2_online_address_classify.restype = None
    lib.h2_online_tasks_initialize.argtypes = [C.POINTER(Memory), C.POINTER(Allocator)]
    lib.h2_online_tasks_initialize.restype = None
    constants = h.read(0x43ff84, 12)
    cases = [constants[:6], constants[6:]]
    for value in cases[:]:
        for byte in range(6):
            changed = bytearray(value)
            changed[byte] ^= 0x80
            cases.append(bytes(changed))
    cases.extend(rng.randbytes(6) for _ in range(16))
    for value in cases:
        h.write(0x4cf7c8, rng.randbytes(16))
        h.write(0x4cf7cc, value)
        h.write(0x50944c, rng.randbytes(8))
        h.call('address_classify', 0x6bfa0, {}, [],
               lambda: lib.h2_online_address_classify(h.memory))
        assert h.read(0x50944e, 1) == bytes([value in (constants[:6], constants[6:])])

    other_identity = h.identity + 0x80
    h.write(other_identity, struct.pack('<I', h.vtable))
    flip = False

    def original_flip(u, address, size, context):
        if flip:
            u.mem_write(0x468758, struct.pack('<I', other_identity))

    hook = h.u.hook_add(U.UC_HOOK_CODE, original_flip, begin=ALLOCATE, end=ALLOCATE)

    def allocate(context, identity, size):
        h.native_events.append((identity, size))
        if flip:
            C.memmove(h.pointer+0x468758-BASE, struct.pack('<I', other_identity), 4)
        return h.allocation

    def release(context, identity, address):
        h.callback_errors.append('unexpected release')

    ops = Allocator(None, AllocFn(allocate), FreeFn(release))
    try:
        for i, value in enumerate(cases):
            for flip in (False, True):
                h.allocation = h.table + i % 4
                h.write(h.table, rng.randbytes(0x250))
                h.write(0x468758, struct.pack('<I', h.identity))
                h.write(0x4cf78c, rng.randbytes(4))
                h.write(0x4cf7cc, value)
                h.write(0x4771c4, rng.randbytes(0x258c))
                h.write(0x50944c, rng.randbytes(8))
                h.original_events.clear()
                h.native_events.clear()
                h.call('tasks_initialize', 0x6b3e0, {}, [],
                       lambda: lib.h2_online_tasks_initialize(h.memory, C.byref(ops)))
                assert h.native_events == [(h.identity, 0x230)]
                assert h.u32(0x4cf78c) == h.allocation
                assert h.u32(h.allocation+0x20) == 24
                assert h.u32(h.allocation+0x24) == 20
                assert h.u32(h.allocation+0x30) == h.identity
                assert h.read(h.allocation+0x29, 2) == b'\x01\x04'
                assert h.read(0x4771c8, 0x2580) == bytes(0x2580)
                assert h.u32(0x479748) == 0xffffffff
    finally:
        h.u.hook_del(hook)
    lib.h2_online_task_find.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32]
    lib.h2_online_task_find.restype=C.c_uint32
    lib.h2_online_task_get.argtypes=[C.POINTER(Memory),C.c_uint32]
    lib.h2_online_task_get.restype=C.c_uint32
    for iteration in range(60):
        array=h.table;bitmap=array+0x300;elements=array+0x400
        limit=[0,1,24,31,32,33,64,65,0xffffffff,0x80000000][iteration%10]
        count=limit if limit<100 else 0
        stride=[20,24,32][iteration%3]
        h.write(array,rng.randbytes(0x1000))
        h.write(0x4cf78c,struct.pack('<I',array))
        for offset,value in [(0x38,limit),(0x24,stride),(0x44,elements),(0x48,bitmap)]:
            h.write(array+offset,struct.pack('<I',value))
        bits=rng.getrandbits(96)
        h.write(bitmap,bits.to_bytes(12,'little'))
        records=[]
        for index in range(count):
            salt=rng.choice([0,1,0x7fff,0x8000,0xffff])
            kind=rng.choice([0,1,11,12,33,0xffffffff]);owner=rng.choice([0,1,255,0xffffffff])
            records.append((salt,kind,owner))
            h.write(elements+index*stride,struct.pack('<HHII',salt,0,kind,owner))
        for kind,owner in [(11,0xffffffff),(12,255),(33,1),(0,0)]:
            value=h.call('task_find',0x6b890,dict(ebx=owner),[kind],
                         lambda:lib.h2_online_task_find(h.memory,kind,owner),0xffffffff)
            expected=any(bits>>i&1 and k==kind and (o==owner or owner in [255,0xffffffff])
                         for i,(_,k,o) in enumerate(records))
            assert value==int(expected)
        indices=[0,max(0,count-1),count,0xffff]
        for index in indices:
            salt=records[index][0] if index<count else 1
            for candidate in [salt,salt^0x8000]:
                handle=(candidate<<16)|index
                value=h.call('task_get',0x6b910,dict(eax=handle),[],
                             lambda:lib.h2_online_task_get(h.memory,handle),0xffffffff)
                expected=elements+index*stride if index<count and candidate and candidate==salt and handle!=0xffffffff else 0
                assert value==expected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', default='build/libhalo2_engine.so')
    parser.add_argument('--report', default='analysis/online-task-tests.json')
    args = parser.parse_args()
    library = (ROOT/args.library).resolve()
    h = Harness(library)
    try:
        suite(h)
    finally:
        h.close()
    sources = ['src/online_tasks.c', 'src/data_array.c',
               'tests/online_tasks_oracle.py', 'tests/hash_crc_oracle.py']
    report = dict(passed=True, xbe_sha256=EXPECTED,
                  library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                  comparisons=h.counts, total_comparisons=sum(h.counts.values()),
                  source_hashes={s: hashlib.sha256((ROOT/s).read_bytes()).hexdigest()
                                 for s in sources},
                  scope='Two online-task setup routines and two lookup helpers; original data-array callees execute unchanged. Allocation boundary controlled, successful allocations only. Lookup bitmap/wildcards/salts and signed limits tested. Full mapped-memory comparison. Task execution and network startup remain incomplete.')
    (ROOT/args.report).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
