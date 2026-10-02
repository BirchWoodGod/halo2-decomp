#!/usr/bin/env python3
"""Arena original/native checks; only platform allocation and save setup are hooked."""
import argparse,ctypes as C,hashlib,json,random,struct
from pathlib import Path
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from allocator_oracle import Allocator
from data_array_oracle import ROOT,Memory,EXPECTED
Allocate=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32)
Prepare=C.CFUNCTYPE(None,C.c_void_p)
Protect=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class Platform(C.Structure):
    _fields_=[('context',C.c_void_p),('allocate',Allocate),('prepare_save_storage',Prepare),('protect',Protect),('close_save_storage',Prepare)]
def suite(h):
    lib=h.lib
    for name,n in [('reserve',1),('reserve_aligned',2),('allocator_allocate',1)]:
        f=getattr(lib,'h2_arena_'+name);f.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*n;f.restype=C.c_uint32
    lib.h2_arena_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Platform)];lib.h2_arena_initialize.restype=None
    lib.h2_arena_allocator_release.argtypes=[C.c_uint32];lib.h2_arena_allocator_release.restype=None
    arena=lib.h2_heap_allocate(h.heap,0x3fe000);assert arena
    original=[];native=[]
    def snapshot(read):return tuple(struct.unpack('<I',read(a,4))[0] for a in [0x4e6080,0x4e6084,0x4e608c,0x510c2c])
    def alloc(ctx,primary,extra):native.append(('allocate',primary,extra,snapshot(h.read)));return arena
    def prepare(ctx):
        native.append(('prepare',snapshot(h.read),h.read(arena,0x3fe000)==bytes(0x3fe000)))
    def protect(ctx,address,size,flags):native.append(('protect',address,size,flags,snapshot(h.read)))
    def close(ctx):native.append(('close',h.read(0x5020d8,4),snapshot(h.read)))
    platform=Platform(None,Allocate(alloc),Prepare(prepare),Protect(protect),Prepare(close))
    for name in ['dispose','initialize_for_map']:
        f=getattr(lib,'h2_arena_'+name);f.argtypes=[C.POINTER(Memory),C.POINTER(Platform)];f.restype=None
    def boundary(u,address,size,ctx):
        if address==0x214f10:
            original.append(('allocate',u.reg_read(X.UC_X86_REG_ECX),u.reg_read(X.UC_X86_REG_EAX),snapshot(u.mem_read)))
            u.reg_write(X.UC_X86_REG_EAX,arena)
        elif address==0x214f80:original.append(('prepare',snapshot(u.mem_read),bytes(u.mem_read(arena,0x3fe000))==bytes(0x3fe000)))
        elif address==0x2150f0:original.append(('close',bytes(u.mem_read(0x5020d8,4)),snapshot(u.mem_read)))
        else:
            esp=u.reg_read(X.UC_X86_REG_ESP)
            original.append(('protect',*struct.unpack('<III',u.mem_read(esp+4,12)),snapshot(u.mem_read)))
        esp=u.reg_read(X.UC_X86_REG_ESP)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+(12 if address==0x2d15da else 0))
    for address in [0x214f10,0x214f80,0x2150f0,0x2d15da]:h.u.hook_add(U.UC_HOOK_CODE,boundary,begin=address,end=address)
    for offset in [0,17,256]:
        for flag in [0,1,255]:
            h.write(arena,b'\xa5'*0x3fe000)
            h.write(0x4e3b60,bytes([flag]));h.write(0x55e755,b'\0')
            h.write(0x4e6080,struct.pack('<IIII',arena,offset,0,0x12345678))
            original.clear();native.clear()
            h.call('initialize',0x123b30,{},[],lambda:lib.h2_arena_initialize(h.memory,C.byref(platform)))
            assert original==native,(original,native)
            assert len(native)==(2 if flag==0 else 0)
            assert h.u32(0x4e6084)==offset+(0x128c if flag==0 else 0)
    # Integrated path: original allocator vtable and pool constructor instructions
    # run unchanged. Native constructors use the recovered arena adapter.
    h.write(0x4e3b60,b'\0');h.write(0x4e6084,struct.pack('<I',0))
    h.call('initialize',0x123b30,{},[],lambda:lib.h2_arena_initialize(h.memory,C.byref(platform)))
    lib.h2_arena_allocator.argtypes=[C.POINTER(Memory)];lib.h2_arena_allocator.restype=Allocator
    ops=lib.h2_arena_allocator(h.memory)
    for name,address in [('command_scripts',0x257d00),('actors',0x1dfae0)]:
        h.call('integrated_'+name,address,{},[],lambda:getattr(lib,'h2_'+name+'_initialize')(h.memory,C.byref(ops)))
    lib.h2_data_dispose.argtypes=[C.POINTER(Memory),C.POINTER(Allocator),C.c_uint32]
    lib.h2_data_dispose.restype=None
    for global_address in [0x502408,0x502404,0x4f55f0]:
        array=h.u32(global_address)
        h.call('integrated_dispose',0x16b5d0,dict(esi=array),[],lambda:lib.h2_data_dispose(h.memory,C.byref(ops),array))
    rng=random.Random(4096)
    for n in range(24):
        h.write(0x4e3b60,rng.randbytes(0x2540))
        h.write(0x4e6080,struct.pack('<I',arena))
        h.write(0x4e6094,struct.pack('<I',arena+0x100))
        h.write(0x4e6948,struct.pack('<I',h.scratch+0x5000))
        h.write(h.scratch+0x5000,rng.randbytes(0x1120))
        name=b'x' * ([0,1,254,255,256,300][n%6])
        h.write(0x5478bc,name+b'\0')
        original.clear();native.clear()
        h.call('initialize_for_map',0x123c20,{},[],lambda:lib.h2_arena_initialize_for_map(h.memory,C.byref(platform)))
        assert original==native and len(native)==2,(original,native)
        assert h.read(arena+0x108,256)==name[:255]+bytes(256-min(len(name),255))
        assert h.read(arena+0x230,0x1118)==h.read(h.scratch+0x5008,0x1118)
        for flag in [0,1,255]:
            h.write(0x4e3b60,bytes([flag]));h.write(0x5020d8,b'\xa5'*4)
            original.clear();native.clear()
            h.call('dispose',0x123bf0,{},[],lambda:lib.h2_arena_dispose(h.memory,C.byref(platform)))
            assert original==native and len(native)==(1 if flag else 0),(original,native)
            if flag:assert h.read(0x4e3b60,0x2540)==bytes(0x2540)
    rng=random.Random(4096)
    for n in range(150):
        size=([0,1,3,4,0xffffffff,0xfffffffd,0x80000000]+[rng.getrandbits(32)])[n%8]
        offset=rng.getrandbits(32);base=rng.getrandbits(32);bits=rng.randrange(256)
        for name,address,regs,args in [
            ('reserve',0x123d40,dict(eax=size),[]),
            ('reserve_aligned',0x123d80,dict(eax=size,ecx=bits),[]),
            ('allocator_allocate',0x124700,dict(ecx=h.identity),[size])]:
            h.write(0x4e6080,struct.pack('<IIII',base,offset,0,rng.getrandbits(32)))
            h.write(0x55e755,bytes([n%2]))
            parameters=[size,bits] if name=='reserve_aligned' else [size]
            h.call(name,address,regs,args,lambda:getattr(lib,'h2_arena_'+name)(h.memory,*parameters),0xffffffff)
        h.call('allocator_release',0x72c70,dict(ecx=h.identity),[size],lambda:lib.h2_arena_allocator_release(size))
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/arena-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library,16*1024*1024)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/arena.c','src/crc.c','tests/arena_oracle.py','tests/hash_crc_oracle.py']},scope='Seven routines; full guest-memory/return checks. Xbox backing allocation, protection, and save-file preparation/closure are controlled boundaries, not implemented services.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
