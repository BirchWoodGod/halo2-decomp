#!/usr/bin/env python3
"""Differential checks for actual engine pool initialization and native mapping.

Only allocator methods are controlled boundaries. All other original engine and
CRT code executes unchanged. The native loader is independently compared with
the existing Python parser's mapping, not with a copy of its own output.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import zlib
import unicorn as U
from unicorn import x86_const as X
from data_array_oracle import ROOT, Memory, XbeParser, EXPECTED
from allocator_oracle import Allocator, AllocFn, FreeFn

BASE,SIZE,STACK,STOP=0x10000,0x800000,0x2000000,0x3000000
ALLOCATE=STOP+0x100

def bind(lib):
    lib.h2_heap_create.argtypes=[C.c_uint32,C.c_uint32];lib.h2_heap_create.restype=C.c_void_p
    lib.h2_heap_destroy.argtypes=[C.c_void_p];lib.h2_heap_destroy.restype=None
    lib.h2_heap_memory.argtypes=[C.c_void_p];lib.h2_heap_memory.restype=C.POINTER(Memory)
    lib.h2_heap_allocate.argtypes=[C.c_void_p,C.c_uint32];lib.h2_heap_allocate.restype=C.c_uint32
    lib.h2_xbe_load.argtypes=[C.c_void_p,C.c_char_p,C.c_char_p,C.c_size_t];lib.h2_xbe_load.restype=C.c_int
    for n in ['h2_command_scripts_initialize','h2_havok_components_initialize','h2_actors_initialize']:
        f=getattr(lib,n);f.argtypes=[C.POINTER(Memory),C.POINTER(Allocator)];f.restype=None

def compare_pool(lib, entry, native_name, fail_mask, flip_allocator, warm_crc=False):
    heap=lib.h2_heap_create(BASE,SIZE)
    assert heap
    try:
        error=C.create_string_buffer(256)
        assert lib.h2_xbe_load(heap,str(ROOT/'default.xbe').encode(),error,256),error.value
        memory=lib.h2_heap_memory(heap)
        native_address=C.addressof(memory.contents.bytes.contents)
        data=(ROOT/'default.xbe').read_bytes()
        assert hashlib.sha256(data).hexdigest()==EXPECTED
        info=XbeParser(data,'default.xbe').parse()
        expected_image=bytearray(SIZE)
        expected_image[:info.size_of_headers]=data[:info.size_of_headers]
        for section in info.sections:
            start=section.virtual_address-BASE
            expected_image[start:start+section.raw_size]=data[section.raw_address:section.raw_address+section.raw_size]
        assert C.string_at(native_address,SIZE)==expected_image
        identity=lib.h2_heap_allocate(heap,16)
        identity2=lib.h2_heap_allocate(heap,16)
        vtable=lib.h2_heap_allocate(heap,16)
        sizes={0x257d00:[0x2174,0x5c8],0x1cec30:[0x1409b],0x1dfae0:[0x8886c,0x203c]}[entry]
        arrays=[lib.h2_heap_allocate(heap,size+32) for size in sizes]
        returns=[0 if fail_mask & (1<<i) else a for i,a in enumerate(arrays)]
        def nw(addr,value): C.memmove(native_address+addr-BASE,struct.pack('<I',value),4)
        def nr(addr): return struct.unpack('<I',C.string_at(native_address+addr-BASE,4))[0]
        nw(identity,vtable);nw(identity2,vtable);nw(vtable,ALLOCATE)
        nw(0x510c2c,identity);nw(0x468758,identity)
        arena=lib.h2_heap_allocate(heap,4096)
        nw(0x4e6080,arena);nw(0x4e6084,0x25);nw(0x4e608c,0x12345678)
        C.memset(native_address+0x55e755-BASE,int(warm_crc),1)
        if warm_crc:
            for i in range(256):
                value=i
                for _ in range(8):value=(value>>1)^(0xedb88320 if value&1 else 0)
                nw(0x55e788+i*4,value)
        for a,size in zip(arrays,sizes): C.memset(native_address+a-BASE,0xa5,size+32)
        initial=C.string_at(native_address,SIZE)
        u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_32)
        u.mem_map(BASE,SIZE);u.mem_write(BASE,initial)
        u.mem_map(STACK,0x10000);u.mem_map(STOP,0x1000)
        u.mem_write(ALLOCATE,b'\xc2\x04\x00')  # controlled allocator returns with ret 4
        original_events=[];native_events=[]
        callback_errors=[]
        result_globals=[0x502408,0x502404,0x51e9b8,0x4f55f0,0x557c6c,0x4f93a0,0x4e6084,0x4e608c]
        def ur(addr): return struct.unpack('<I',u.mem_read(addr,4))[0]
        def original_allocate(uc,addr,size,_):
            if addr!=ALLOCATE:return
            identity_arg=uc.reg_read(X.UC_X86_REG_ECX)
            requested=ur(uc.reg_read(X.UC_X86_REG_ESP)+4)
            index=len(original_events)
            original_events.append((identity_arg,requested,tuple(ur(g) for g in result_globals)))
            assert index<len(returns)
            if flip_allocator and index==0:u.mem_write(0x510c2c,struct.pack('<I',identity2))
            uc.reg_write(X.UC_X86_REG_EAX,returns[index])
        u.hook_add(U.UC_HOOK_CODE,original_allocate,begin=ALLOCATE,end=ALLOCATE)
        def native_allocate(ctx,identity_arg,requested):
            index=len(native_events)
            native_events.append((identity_arg,requested,tuple(nr(g) for g in result_globals)))
            if index>=len(returns):
                callback_errors.append('unexpected allocation');return 0
            if flip_allocator and index==0:nw(0x510c2c,identity2)
            return returns[index]
        def native_free(ctx,identity_arg,array):callback_errors.append('unexpected free')
        ops=Allocator(None,AllocFn(native_allocate),FreeFn(native_free))
        esp=STACK+0x8000
        u.reg_write(X.UC_X86_REG_ESP,esp);u.reg_write(X.UC_X86_REG_EFLAGS,2)
        u.mem_write(esp,struct.pack('<I',STOP))
        u.emu_start(entry,STOP,timeout=5_000_000,count=2_000_000)
        assert u.reg_read(X.UC_X86_REG_EIP)==STOP and u.reg_read(X.UC_X86_REG_ESP)==esp+4
        getattr(lib,native_name)(memory,C.byref(ops))
        assert not callback_errors,callback_errors
        assert native_events==original_events,(native_events,original_events)
        assert [event[1] for event in native_events]==sizes
        original=bytes(u.mem_read(BASE,SIZE));native=C.string_at(native_address,SIZE)
        if original!=native:
            at=next(i for i,(a,b) in enumerate(zip(original,native)) if a!=b)
            raise AssertionError((native_name,fail_mask,hex(BASE+at),original[at:at+16].hex(),native[at:at+16].hex()))
        outputs={0x257d00:[0x502408,0x502404],0x1cec30:[0x51e9b8],0x1dfae0:[0x4f55f0,0x557c6c]}[entry]
        for i,g in enumerate(outputs):
            assert nr(g)==returns[i]
        if entry==0x1dfae0:
            assert nr(0x4e6084)==0x665 and nr(0x4f93a0)==arena+0x25
            assert nr(0x4e608c)==zlib.crc32(struct.pack('<I',0x640),0x12345678^0xffffffff)^0xffffffff
        return dict(function=f'{entry:08x}',failure_mask=fail_mask,allocator_changed=flip_allocator,
                    warm_crc=warm_crc,compared_bytes=SIZE,allocator_calls=len(native_events))
    finally:lib.h2_heap_destroy(heap)

def loader_failures(lib):
    heap=lib.h2_heap_create(BASE,SIZE);error=C.create_string_buffer(256)
    assert heap
    cases=0
    try:
        assert not lib.h2_xbe_load(heap,b'/nonexistent/halo2-test-input',error,256);cases+=1
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'input.xbe'
            for payload in [b'',b'XBEH',bytes(0x178)]:
                path.write_bytes(payload)
                assert not lib.h2_xbe_load(heap,str(path).encode(),error,256);cases+=1
            payload=bytearray((ROOT/'default.xbe').read_bytes());payload[-1]^=1
            path.write_bytes(payload)
            assert not lib.h2_xbe_load(heap,str(path).encode(),error,256)
            assert b'SHA-256' in error.value;cases+=1
        assert lib.h2_xbe_load(heap,str(ROOT/'default.xbe').encode(),error,256)
        assert not lib.h2_xbe_load(heap,str(ROOT/'default.xbe').encode(),error,256);cases+=1
    finally:lib.h2_heap_destroy(heap)
    return cases

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,default=ROOT/'build/libhalo2_engine.so')
    ap.add_argument('--report',type=Path,default=ROOT/'analysis/engine-pool-tests.json');args=ap.parse_args()
    lib=C.CDLL(str(args.library.resolve()));bind(lib)
    results=[]
    for mask in range(4):
        for flip in [False,True]:results.append(compare_pool(lib,0x257d00,'h2_command_scripts_initialize',mask,flip))
    for mask in range(2):results.append(compare_pool(lib,0x1cec30,'h2_havok_components_initialize',mask,False))
    for mask in range(4):
        for flip in [False,True]:
            for warm in [False,True]:
                results.append(compare_pool(lib,0x1dfae0,'h2_actors_initialize',mask,flip,warm))
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                comparisons=results,loader_rejections=loader_failures(lib),
                source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
                    ['src/engine_pools.c','src/xbe_image.c','src/crc.c','src/hash_table.c','tests/engine_pools_oracle.py']},
                scope='Three original engine pool initializers including actors, allocator boundary controlled; image bytes independently checked. Not a game boot.')
    args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
