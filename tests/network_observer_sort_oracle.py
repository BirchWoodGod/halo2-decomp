#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x13de30);array=h.table;data=array+0x1000;original=[];native=[];calls=0
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    comp=h.lib.h2_network_observer_compare_priority;comp.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;comp.restype=C.c_uint8
    CB=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
    def callback(ctx,a,b,d):
        native.append((a,b,d,h.read(array,256)));return comp(h.memory,a,b,d)
    cb=CB(callback)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);a,b,d=struct.unpack('<III',u.mem_read(sp+4,12));original.append((a,b,d,bytes(u.mem_read(array,256))))
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x78a90,end=0x78a90)
    for name in ['h2_sort_u32','h2_sort_u32_small']:
        fn=getattr(h.lib,name);fn.argtypes=[C.POINTER(Memory),CB,C.c_void_p]+[C.c_uint32]*3;fn.restype=None
    values=[0,0x80000000,0x3f800000,0xbf800000,0x7f800000,0xff800000,0x7fc12345,1,0x80000001]
    for case in range(512):
        h.write(data,b''.join(pack(rng.choice(values)) for _ in range(64)));h.write(array,b''.join(pack(rng.randrange(64)) for _ in range(64)))
        a,b=rng.randrange(64),rng.randrange(64)
        h.call('compare',0x78a90,{},[a,b,data],lambda:comp(h.memory,a,b,data),255)
        for small in [True,False]:
            original.clear();native.clear();count=case%65
            fn=h.lib.h2_sort_u32_small if small else h.lib.h2_sort_u32
            last=array+max(count-1,0)*4
            regs=dict(eax=last) if small else dict(eax=count,ecx=array)
            args=[array if small else 0,0x78a90,data]
            h.call('small' if small else 'sort',0x13e0e0 if small else 0x13de30,regs,args,lambda:fn(h.memory,cb,None,array,last if small else count,data))
            assert original==native,(case,small)
            calls+=len(original)
    return {'comparator_calls':calls}

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-sort-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    files=['src/network_observer_sort.c','include/halo2/network_observer_sort.h','tests/network_observer_sort_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original priority comparator, small selection sort and iterative quicksort. Exact full memory plus comparator arguments/order and array snapshots. Counts 0..64, repeated priorities, signed zeros, quiet NaN, infinity and subnormals. Valid disjoint arrays; priority comparator only, no arbitrary mutating comparator tested.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
