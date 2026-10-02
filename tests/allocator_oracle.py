#!/usr/bin/env python3
"""Original data-array create/dispose vs native C, at the allocator boundary.

The oracle uses the original engine/CRT instructions and two tiny test allocator
methods (allocate returns a supplied address; release logs the cleared header).
The native side uses callbacks with the same boundary contract. This does not
verify an Xbox kernel allocator. Separate tests exercise the real Linux heap.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import struct
from data_array_oracle import Oracle, Memory, ROOT, BASE, STACK, STOP, NAME, REGS, X, EXPECTED

ALLOCATOR, VTABLE, STATE = BASE+0x80, BASE+0x90, BASE+0xc0
CREATE, DISPOSE = 0x16b570, 0x16b5d0
AllocFn = C.CFUNCTYPE(C.c_uint32, C.c_void_p, C.c_uint32, C.c_uint32)
FreeFn = C.CFUNCTYPE(None, C.c_void_p, C.c_uint32, C.c_uint32)

class Allocator(C.Structure):
    _fields_ = [('context',C.c_void_p),('allocate',AllocFn),('release',FreeFn)]

class AllocOracle(Oracle):
    def __init__(self, library):
        super().__init__(library)
        self.lib.h2_data_create.argtypes = [C.POINTER(Memory),C.POINTER(Allocator)] + [C.c_uint32]*5
        self.lib.h2_data_create.restype = C.c_uint32
        self.lib.h2_data_dispose.argtypes = [C.POINTER(Memory),C.POINTER(Allocator),C.c_uint32]
        self.lib.h2_data_dispose.restype = None
        def get(a): return self.u32(a)
        def put(a,v): struct.pack_into('<I',self.buf,a-BASE,v & 0xffffffff)
        def allocate(ctx,identity,size):
            put(STATE+4,size); put(STATE+8,identity); put(STATE+12,get(STATE+12)+1)
            return get(STATE)
        def release(ctx,identity,array):
            put(STATE+16,array); put(STATE+20,identity); put(STATE+24,get(STATE+24)+1)
            put(STATE+28,get(array))
        self.ops = Allocator(None,AllocFn(allocate),FreeFn(release))
        def addr(a): return struct.pack('<I',a)
        allocate_code = (b'\x8b\x44\x24\x04\xa3'+addr(STATE+4)+b'\x89\x0d'+addr(STATE+8)+
                         b'\xff\x05'+addr(STATE+12)+b'\xa1'+addr(STATE)+b'\xc2\x04\x00')
        release_code = (b'\x8b\x44\x24\x04\xa3'+addr(STATE+16)+b'\x89\x0d'+addr(STATE+20)+
                        b'\xff\x05'+addr(STATE+24)+b'\x8b\x00\xa3'+addr(STATE+28)+b'\xc2\x04\x00')
        self.uc.mem_write(STOP+0x100,allocate_code)
        self.uc.mem_write(STOP+0x180,release_code)
        self.boundary_checks = 0

    def run_original(self, entry, registers, stack_args):
        for i,r in enumerate(REGS.values()): self.uc.reg_write(r,0x65430000+i)
        for reg,value in registers.items(): self.uc.reg_write(REGS[reg],value)
        esp=STACK+0x8000
        self.uc.reg_write(X.UC_X86_REG_EFLAGS,2)
        self.uc.reg_write(X.UC_X86_REG_ESP,esp)
        self.uc.mem_write(esp,struct.pack('<'+'I'*(len(stack_args)+1),STOP,*stack_args))
        self.uc.emu_start(entry,STOP,timeout=5_000_000,count=2_000_000)
        assert self.uc.reg_read(X.UC_X86_REG_EIP)==STOP
        assert self.uc.reg_read(X.UC_X86_REG_ESP)==esp+4+len(stack_args)*4
        return self.uc.reg_read(X.UC_X86_REG_EAX)

    def compare(self):
        original=bytes(self.uc.mem_read(BASE,self.span)); native=bytes(self.buf[:self.span])
        if original!=native:
            at=next(i for i,(a,b) in enumerate(zip(original,native)) if a!=b)
            raise AssertionError((hex(BASE+at),original[at:at+16].hex(),native[at:at+16].hex()))
        self.boundary_checks+=1

    def transaction(self, capacity,stride,alignment,offset,fail=False,name=b'actors'):
        # Reserve space and dirty bytes, then test the allocator-taking constructor.
        self.reset(capacity,stride,alignment,name=name,offset=offset)
        self.write(self.array,bytes([0x5a])*0x4c)
        self.write(ALLOCATOR,struct.pack('<I',VTABLE))
        self.write(VTABLE,struct.pack('<II',STOP+0x100,STOP+0x180))
        self.write(STATE,struct.pack('<8I',0 if fail else self.array,0,0,0,0,0,0,0))
        expected=self.run_original(CREATE,dict(eax=capacity,edi=ALLOCATOR),[NAME,stride,alignment])
        actual=self.lib.h2_data_create(C.byref(self.mem),C.byref(self.ops),ALLOCATOR,NAME,capacity,stride,alignment)
        assert actual==expected
        self.compare()
        assert self.u32(STATE+12)==1
        if actual:
            assert self.u32(actual+0x30)==ALLOCATOR
            self.run_original(DISPOSE,dict(esi=actual),[])
            self.lib.h2_data_dispose(C.byref(self.mem),C.byref(self.ops),actual)
            self.compare()
            assert self.u32(STATE+24)==1 and self.u32(STATE+28)==0
            assert bytes(self.buf[actual-BASE:actual-BASE+0x4c])==bytes(0x4c)
        else: assert self.u32(STATE+24)==0

def test_linux_heap(lib):
    lib.h2_heap_create.argtypes=[C.c_uint32,C.c_uint32];lib.h2_heap_create.restype=C.c_void_p
    lib.h2_heap_destroy.argtypes=[C.c_void_p];lib.h2_heap_destroy.restype=None
    lib.h2_heap_memory.argtypes=[C.c_void_p];lib.h2_heap_memory.restype=C.POINTER(Memory)
    lib.h2_heap_allocator.argtypes=[C.c_void_p];lib.h2_heap_allocator.restype=Allocator
    lib.h2_heap_allocate.argtypes=[C.c_void_p,C.c_uint32];lib.h2_heap_allocate.restype=C.c_uint32
    lib.h2_heap_release.argtypes=[C.c_void_p,C.c_uint32];lib.h2_heap_release.restype=C.c_int
    for name in ['h2_heap_live_allocations','h2_heap_bytes_in_use']:
        f=getattr(lib,name);f.argtypes=[C.c_void_p];f.restype=C.c_size_t
    for base,size in [(0,4096),(1,4096),(BASE,0),(BASE,4095),(0xfffff000,8192)]:
        assert not lib.h2_heap_create(base,size)
    heap=lib.h2_heap_create(BASE,0x100000)
    assert heap
    rng=random.Random(0x5849)
    operations=0
    try:
        memory=lib.h2_heap_memory(heap)
        ops=lib.h2_heap_allocator(heap)
        names=lib.h2_heap_allocate(heap,128)
        C.memmove(C.addressof(memory.contents.bytes.contents),b'actors\0'+bytes(121),128)
        arrays=[]
        for count,stride in [(256,0x888),(40,0xd4),(10,0x8c)]:
            a=lib.h2_data_create(memory,C.byref(ops),0x12345678,names,count,stride,4)
            assert a and a%16==0
            arrays.append(a)
            lib.h2_data_activate(memory,a)
            handles=[lib.h2_data_new(memory,a) for _ in range(count)]
            assert len(set(handles))==count and lib.h2_data_new(memory,a)==0xffffffff
            for h in handles: assert lib.h2_data_get(memory,a,h)
        for a in arrays: lib.h2_data_dispose(memory,C.byref(ops),a)
        assert lib.h2_heap_live_allocations(heap)==1
        assert lib.h2_heap_release(heap,names)==1
        assert lib.h2_heap_release(heap,names)==0
        assert lib.h2_heap_allocate(heap,0)==0
        assert lib.h2_heap_allocate(heap,0xffffffff)==0
        live={}
        for _ in range(3000):
            if live and rng.randrange(3)==0:
                address=rng.choice(list(live)); size,pattern=live.pop(address)
                actual=C.string_at(C.addressof(memory.contents.bytes.contents)+address-BASE,size)
                assert actual==pattern
                assert not lib.h2_heap_release(heap,address+1)
                assert lib.h2_heap_release(heap,address)==1
                assert lib.h2_heap_release(heap,address)==0
            else:
                size=rng.randrange(1,32000)
                address=lib.h2_heap_allocate(heap,size)
                if address:
                    assert address%16==0
                    assert all(address+size<=a or a+s<=address for a,(s,_) in live.items())
                    pattern=bytes([rng.randrange(256)])*size
                    C.memmove(C.addressof(memory.contents.bytes.contents)+address-BASE,pattern,size)
                    live[address]=(size,pattern)
            operations+=1
            assert lib.h2_heap_live_allocations(heap)==len(live)
            assert lib.h2_heap_bytes_in_use(heap)==sum((s+15)&~15 for s,_ in live.values())
        for address,(size,pattern) in live.items():
            assert C.string_at(C.addressof(memory.contents.bytes.contents)+address-BASE,size)==pattern
            assert lib.h2_heap_release(heap,address)==1
        assert lib.h2_heap_bytes_in_use(heap)==0
        all_memory=lib.h2_heap_allocate(heap,0x100000)
        assert all_memory==BASE and lib.h2_heap_allocate(heap,1)==0
        assert lib.h2_heap_release(heap,all_memory)==1
    finally: lib.h2_heap_destroy(heap)
    return operations

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--library',type=Path,default=ROOT/'build/libhalo2_engine.so')
    ap.add_argument('--report',type=Path,default=ROOT/'analysis/allocator-tests.json')
    args=ap.parse_args()
    o=AllocOracle(args.library.resolve())
    rng=random.Random(0x16b570)
    for i in range(160):
        o.transaction(rng.choice([0,1,10,31,32,33,40,256]),rng.choice([2,3,7,0x8c,0xd4,0x888]),
                      rng.randrange(7),rng.randrange(0x101,0x130),fail=i%5==0,
                      name=rng.choice([b'',b'a',b'command scripts',b'a'*70]))
    # Zero allocator identity still clears the header, with no callback.
    o.reset(3,5);o.write(o.array+0x30,bytes(4))
    o.run_original(DISPOSE,dict(esi=o.array),[])
    o.lib.h2_data_dispose(C.byref(o.mem),C.byref(o.ops),o.array);o.compare()
    operations=test_linux_heap(o.lib)
    sources={str(p):hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
             ['src/data_array.c','src/data_array_alloc.c','src/heap.c','tests/allocator_oracle.py']}
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                source_hashes=sources,engine_boundary_comparisons=o.boundary_checks,heap_stress_operations=operations,
                actual_pool_sizes_tested=['256*0x888','40*0xd4','10*0x8c'],
                scope='Original create/dispose with controlled allocator methods; native Linux heap tested separately. No whole-game run.')
    args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
