#!/usr/bin/env python3
"""Random-state startup and deterministic direction selection against original x86."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from data_array_oracle import ROOT,Memory,EXPECTED
from hash_crc_oracle import Harness
from game_lifecycle_oracle import Operations,FP,Dispatch
from arena_oracle import Platform
Source=C.CFUNCTYPE(C.c_uint32,C.c_void_p)
class Sources(C.Structure):
    _fields_=[('context',C.c_void_p),('time_value',Source),('crt_random',Source),('tick_value',Source)]
def suite(h):
    lib=h.lib;rng=random.Random(146240);original=[];native=[];values=[0,0,0];flip=False
    seed=h.scratch+0x6000;alternate=seed+0x100;output=seed+0x200
    def snapshot(read):
        address=struct.unpack('<I',read(0x4e7408,4))[0]
        return (address,bytes(read(address,8)),bytes(read(0x4e6084,12)))
    def native_source(index):
        native.append((index,snapshot(h.read)))
        if flip and index==2:C.memmove(h.pointer+0x4e7408-0x10000,struct.pack('<I',alternate),4)
        return values[index]
    sources=Sources(None,*[Source(lambda ctx,i=i:native_source(i)) for i in range(3)])
    addresses=[0x321aae,0x321f75,0x3314b0]
    def hook(u,address,size,ctx):
        index=addresses.index(address);esp=u.reg_read(X.UC_X86_REG_ESP)
        if index==0:assert struct.unpack('<I',u.mem_read(esp+4,4))[0]==0
        original.append((index,snapshot(u.mem_read)))
        if flip and index==2:u.mem_write(0x4e7408,struct.pack('<I',alternate))
        u.reg_write(X.UC_X86_REG_EAX,values[index]);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    for address in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    lib.h2_random_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Sources)];lib.h2_random_initialize.restype=None
    lib.h2_random_generate_seed.argtypes=[C.POINTER(Sources)];lib.h2_random_generate_seed.restype=C.c_uint32
    lib.h2_random_direction.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];lib.h2_random_direction.restype=None
    lib.h2_lifecycle_noop.argtypes=[];lib.h2_lifecycle_noop.restype=None
    for n in range(48):
        values=[rng.getrandbits(32) for _ in range(3)];flip=bool(n%2)
        h.write(seed,rng.randbytes(0x300));h.write(0x4e7408,struct.pack('<I',seed))
        h.write(0x4e6080,struct.pack('<IIII',seed,n%4,0,0xffffffff));h.write(0x55e755,bytes([n%2]))
        original.clear();native.clear()
        h.call('initialize',0x146240,{},[],lambda:lib.h2_random_initialize(h.memory,C.byref(sources)))
        assert original==native and [e[0] for e in native]==[0,1,2]
        assert h.u32((alternate if flip else seed+n%4)+4)==values[0]^values[1]^values[2]
        original.clear();native.clear()
        result=h.call('generate_seed',0x1462b0,{},[],lambda:lib.h2_random_generate_seed(C.byref(sources)),0xffffffff)
        assert result==values[0]^values[1]^values[2] and original==native
    lib.h2_game_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Platform),C.POINTER(Operations)]
    lib.h2_game_initialize.restype=None
    native_calls=[];original_calls=[]
    def dispatch(ctx,function):
        native_calls.append(function)
        if function==0x146240:lib.h2_random_initialize(h.memory,C.byref(sources))
        elif function==0x175f40:lib.h2_lifecycle_noop()
    operations=Operations(None,FP(lambda ctx,v,m:None),Dispatch(dispatch),Dispatch(lambda ctx,p:None))
    platform=Platform();targets={h.u32(0x440dd8+i*36) for i in range(68)}
    def lifecycle_hook(u,address,size,ctx):
        if address not in targets and address!=0x3212d6:return
        esp=u.reg_read(X.UC_X86_REG_ESP);ret=struct.unpack('<I',u.mem_read(esp,4))[0]
        if address in targets:
            if ret!=0x137c8c:return
            original_calls.append(address)
            if address in [0x146240,0x175f40]:return
        u.reg_write(X.UC_X86_REG_EIP,ret);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    handle=h.u.hook_add(U.UC_HOOK_CODE,lifecycle_hook)
    for n in range(4):
        flip=bool(n%2);values=[rng.getrandbits(32) for _ in range(3)]
        h.write(0x4e3b60,b'\1');h.write(0x4e6080,struct.pack('<IIII',seed+0x1000,0,0,0xffffffff))
        original.clear();native.clear();original_calls.clear();native_calls.clear()
        h.call('integrated_initialize',0x137c20,{},[],lambda:lib.h2_game_initialize(h.memory,C.byref(platform),C.byref(operations)))
        assert original==native and original_calls==native_calls and len(native_calls)==68
    h.u.hook_del(handle)
    # Reach every one of the 1026 table entries using the inverse LCG, plus
    # overlapping output/seed cases. Copy raw floats as the original does.
    inverse=pow(0x19660d,-1,1<<32)
    for index in range(1026):
        high=(index*65536+1025)//1026
        next_seed=high<<16
        initial=((next_seed-0x3c6ef35f)*inverse)&0xffffffff
        h.write(seed,struct.pack('<I',initial))
        target=seed if index%5==0 else output
        expected=h.read(0x4417f0+index*12,12)
        h.call('direction',0x1462e0,dict(eax=target,edx=seed),[],lambda:lib.h2_random_direction(h.memory,target,seed))
        assert h.read(target,12)==expected
        if target!=seed:assert h.u32(seed)==next_seed
    h.call('lifecycle_noop',0x175f40,{},[],lib.h2_lifecycle_noop)
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/random-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/random.c','tests/random_oracle.py','tests/hash_crc_oracle.py']},scope='Three random routines and a shared return stub. CRT/SDK entropy calls are controlled; all direction-table entries compared. Not complete random math or game startup.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
