#!/usr/bin/env python3
"""Original x86 versus recovered CRC/hash-table C, with actual actor key callbacks.
Only constructor allocation is a controlled external boundary. Heap/image setup
uses the native loader independently verified by engine_pools_oracle.py.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import struct
import zlib
import unicorn as U
from unicorn import x86_const as X
from engine_pools_oracle import BASE,SIZE,STACK,STOP,ALLOCATE,bind
from data_array_oracle import ROOT,Memory,EXPECTED,REGS
from allocator_oracle import Allocator,AllocFn,FreeFn

HashFn=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32)
EqualFn=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class KeyOps(C.Structure):
    _fields_=[('context',C.c_void_p),('hash',HashFn),('equal',EqualFn)]

class Harness:
    def __init__(self,library,size=SIZE):
        self.size=size
        self.lib=C.CDLL(str(library));bind(self.lib)
        self.heap=self.lib.h2_heap_create(BASE,self.size)
        assert self.heap
        error=C.create_string_buffer(256)
        assert self.lib.h2_xbe_load(self.heap,str(ROOT/'default.xbe').encode(),error,256),error.value
        self.memory=self.lib.h2_heap_memory(self.heap)
        self.pointer=C.addressof(self.memory.contents.bytes.contents)
        self.scratch=self.lib.h2_heap_allocate(self.heap,0x20000)
        assert self.scratch
        self.identity=self.scratch;self.vtable=self.scratch+16;self.name=self.scratch+32
        self.payload=self.scratch+0x100;self.table=self.scratch+0x2000
        self.crc=self.scratch+0x1800
        self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_32)
        self.u.mem_map(BASE,self.size);self.u.mem_write(BASE,C.string_at(self.pointer,self.size))
        self.u.mem_map(STACK,0x10000);self.u.mem_map(STOP,0x1000)
        self.u.mem_write(ALLOCATE,b'\xc2\x04\x00')
        self.write(self.identity,struct.pack('<I',self.vtable));self.write(self.vtable,struct.pack('<I',ALLOCATE))
        self.original_events=[];self.native_events=[];self.callback_errors=[]
        self.allocation=self.table;self.counts={}
        def original_allocator(u,address,size,_):
            esp=u.reg_read(X.UC_X86_REG_ESP)
            request=struct.unpack('<I',u.mem_read(esp+4,4))[0]
            self.original_events.append((u.reg_read(X.UC_X86_REG_ECX),request))
            u.reg_write(X.UC_X86_REG_EAX,self.allocation)
        self.u.hook_add(U.UC_HOOK_CODE,original_allocator,begin=ALLOCATE,end=ALLOCATE)
        def native_allocator(ctx,identity,size):self.native_events.append((identity,size));return self.allocation
        def native_free(ctx,identity,address):self.callback_errors.append('unexpected free')
        self.allocator=Allocator(None,AllocFn(native_allocator),FreeFn(native_free))
        self.lib.h2_actor_owner_key_ops.restype=KeyOps
        self.keys=self.lib.h2_actor_owner_key_ops()
        self.lib.h2_hash_create.argtypes=[C.POINTER(Memory),C.POINTER(Allocator)]+[C.c_uint32]*7
        self.lib.h2_hash_create.restype=C.c_uint32
        self.lib.h2_hash_clear.argtypes=[C.POINTER(Memory),C.c_uint32];self.lib.h2_hash_clear.restype=None
        for n,argc,ret in [('insert',3,C.c_uint8),('find',2,C.c_uint32),('remove',2,C.c_uint8)]:
            f=getattr(self.lib,'h2_hash_'+n);f.argtypes=[C.POINTER(Memory),C.POINTER(KeyOps)]+[C.c_uint32]*argc;f.restype=ret
        self.lib.h2_crc_update.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;self.lib.h2_crc_update.restype=None
        self.lib.h2_crc_table_initialize.argtypes=[C.POINTER(Memory),C.c_uint32];self.lib.h2_crc_table_initialize.restype=None
        self.lib.h2_actor_owner_hash.argtypes=[C.c_uint32];self.lib.h2_actor_owner_hash.restype=C.c_uint32
        self.lib.h2_actor_owner_equal.argtypes=[C.c_uint32,C.c_uint32];self.lib.h2_actor_owner_equal.restype=C.c_uint8

    def close(self):self.lib.h2_heap_destroy(self.heap)
    def write(self,address,data):
        assert BASE<=address and address+len(data)<=BASE+self.size
        C.memmove(self.pointer+address-BASE,data,len(data));self.u.mem_write(address,data)
    def read(self,address,size):return C.string_at(self.pointer+address-BASE,size)
    def u32(self,address):return struct.unpack('<I',self.read(address,4))[0]
    def call(self,label,address,registers,stack_args,native,mask=None):
        for i,r in enumerate(REGS.values()):self.u.reg_write(r,0xabc00000+i)
        for reg,value in registers.items():self.u.reg_write(REGS[reg],value)
        esp=STACK+0x8000
        self.u.mem_write(esp,struct.pack('<'+'I'*(1+len(stack_args)),STOP,*stack_args))
        self.u.reg_write(X.UC_X86_REG_ESP,esp);self.u.reg_write(X.UC_X86_REG_EFLAGS,2)
        self.u.emu_start(address,STOP,timeout=5_000_000,count=2_000_000)
        assert self.u.reg_read(X.UC_X86_REG_EIP)==STOP,(label,'return')
        assert self.u.reg_read(X.UC_X86_REG_ESP)==esp+4+len(stack_args)*4,(label,'stack')
        eax=self.u.reg_read(X.UC_X86_REG_EAX)
        result=native()
        assert not self.callback_errors,self.callback_errors
        assert self.original_events==self.native_events
        if mask is not None:assert result==eax&mask,(label,result,eax)
        original=bytes(self.u.mem_read(BASE,self.size));actual=C.string_at(self.pointer,self.size)
        if original!=actual:
            at=next(i for i,(a,b) in enumerate(zip(original,actual)) if a!=b)
            raise AssertionError((label,hex(BASE+at),original[at:at+16].hex(),actual[at:at+16].hex()))
        self.counts[label]=self.counts.get(label,0)+1
        return result

    def create(self,capacity,payload,buckets,fail=False,name=b'owners'):
        self.write(self.name,name+b'\0')
        self.write(self.table,b'\xa5'*0x10000)
        self.allocation=0 if fail else self.table
        return self.call('hash_create',0x13e1a0,dict(ebx=capacity,edi=self.identity),
            [self.name,payload,buckets,0x25dd20,0x25dd30],
            lambda:self.lib.h2_hash_create(self.memory,C.byref(self.allocator),self.identity,self.name,
                capacity,payload,buckets,0x25dd20,0x25dd30),0xffffffff)
    def insert(self,key):
        return self.call('hash_insert',0x13e270,dict(ebx=self.table,eax=key),[self.payload],
            lambda:self.lib.h2_hash_insert(self.memory,C.byref(self.keys),self.table,key,self.payload),255)
    def find(self,key):
        return self.call('hash_find',0x13e2d0,dict(edi=self.table),[key],
            lambda:self.lib.h2_hash_find(self.memory,C.byref(self.keys),self.table,key),0xffffffff)
    def remove(self,key):
        return self.call('hash_remove',0x13e320,dict(edi=self.table),[key],
            lambda:self.lib.h2_hash_remove(self.memory,C.byref(self.keys),self.table,key),255)
    def clear(self):
        self.call('hash_clear',0x13e210,dict(edx=self.table),[],lambda:self.lib.h2_hash_clear(self.memory,self.table))

def suite(h):
    rng=random.Random(0x1dfae0)
    for capacity,payload,buckets in [(0,0,1),(1,1,1),(7,3,3),(9,7,1),(31,4,17),(32,16,1024),(256,4,1024)]:
        assert h.create(capacity,payload,buckets,True)==0
        h.create(capacity,payload,buckets,name=rng.choice([b'',b'a',b'actor firing-position owners',b'X'*50]))
        # Duplicate keys are permitted; newest matching node wins. Fill all
        # slots, force collisions, and prove exhaustion doesn't consume a node.
        model={}
        for i in range(capacity):
            key=(i%4)*256;value=rng.randbytes(payload)
            h.write(h.payload,value)
            assert h.insert(key)==1;model.setdefault(key,[]).insert(0,value)
        assert h.insert(123)==0
        for step in range(100):
            key=rng.choice([0,256,512,768,0xffffffff,123])
            op=rng.randrange(3)
            if op==0:
                value=rng.randbytes(payload);h.write(h.payload,value)
                expected=int(sum(map(len,model.values()))<capacity)
                assert h.insert(key)==expected
                if expected:model.setdefault(key,[]).insert(0,value)
            elif op==1:
                found=h.find(key)
                assert bool(found)==bool(model.get(key))
                if found:assert h.read(found+12,payload)==model[key][0]
            else:
                assert h.remove(key)==int(bool(model.get(key)))
                if model.get(key):model[key].pop(0)
        h.clear()
        for key in model:assert h.find(key)==0
    for _ in range(80):
        key=rng.getrandbits(32);right=rng.choice([key,rng.getrandbits(32)])
        h.call('owner_hash',0x25dd20,{},[key],lambda:h.lib.h2_actor_owner_hash(key),0xffffffff)
        h.call('owner_equal',0x25dd30,{},[key,right],lambda:h.lib.h2_actor_owner_equal(key,right),255)
    # Raw CRC seed and final-XOR convention independently checked with zlib.
    table=h.scratch+0x1a01
    h.call('crc_table',0x163c00,dict(edx=table),[],lambda:h.lib.h2_crc_table_initialize(h.memory,table))
    for cold in [False,True]:
        for length in [0,1,2,3,4,7,31,255,256,257,4096,0xffffffff,0x80000000]:
            h.write(0x55e755,bytes([0 if cold else 1]))
            if not cold:
                h.call('crc_table',0x163c00,dict(edx=0x55e788),[],lambda:h.lib.h2_crc_table_initialize(h.memory,0x55e788))
            seed=rng.getrandbits(32);h.write(h.crc,struct.pack('<I',seed))
            payload=rng.randbytes(length if length<0x80000000 else 0)
            h.write(h.payload,payload)
            address=h.payload if payload else 0xffffffff
            h.call('crc_update',0x163ba0,dict(eax=address,edi=length),[h.crc],
                lambda:h.lib.h2_crc_update(h.memory,h.crc,address,length))
            assert h.u32(h.crc)==zlib.crc32(payload,seed^0xffffffff)^0xffffffff
    # Split updates equal a single update when carrying the raw accumulator.
    data=rng.randbytes(97);seed=0x12345678;h.write(h.crc,struct.pack('<I',seed))
    for chunk in [data[:31],data[31:]]:
        h.write(h.payload,chunk)
        h.call('crc_update',0x163ba0,dict(eax=h.payload,edi=len(chunk)),[h.crc],
            lambda:h.lib.h2_crc_update(h.memory,h.crc,h.payload,len(chunk)))
    assert h.u32(h.crc)==zlib.crc32(data,seed^0xffffffff)^0xffffffff

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,default=ROOT/'build/libhalo2_engine.so')
    ap.add_argument('--report',type=Path,default=ROOT/'analysis/hash-crc-tests.json');args=ap.parse_args()
    h=Harness(args.library.resolve())
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),
        source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
            ['src/hash_table.c','src/crc.c','tests/hash_crc_oracle.py']},
        scope='Nine routines; original hash/CRC/key callback instructions; constructor allocator controlled; full guest memory compared. Not whole-game correctness.')
    args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
