#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x820f0);base=h.table;alternate=base+0xb000;scratch=base+0xa200;original=[];native=[];coverage={'ticks':0,'success':0,'failure':0};iteration=0;stride=0;selected=0
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events):
        events.append((bytes(read(base,0xa140)),bytes(read(0x4d87d0,16))))
        if events is original:coverage['ticks']+=1
        if iteration%3==0:
            write(0x4d87d8,pack(alternate));write(0x4d87d0,pack(0));write(0x4d8ba0,b'\0')
            write(base+selected*stride+8,pack(0xdeadbeef))
        write(0x4cf6e8,pack(iteration))
        return [0,1,0xffffffff,0x80000000][iteration//2%4]
    tick=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,tick,Provider())
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);value=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    stream=h.lib.h2_network_stream_allocate;stream.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];stream.restype=C.c_uint32
    storage=h.lib.h2_network_storage_allocate;storage.argtypes=[C.POINTER(Memory),C.c_void_p,C.c_uint32,C.c_uint32];storage.restype=C.c_uint32
    for mode,stride,address in [('stream',0x97c,0x820f0),('storage',0x2850,0x82150)]:
        for iteration in range(512):
            original.clear();native.clear();h.write(base,rng.randbytes(0xa140));h.write(alternate,rng.randbytes(0x1000));seed=rng.randbytes(8);h.write(scratch,seed)
            count=[0,1,2,4,0xffffffff,0x80000000][iteration%6];enabled=iteration//6%3;mask=iteration//18%16;owner=rng.getrandbits(32)
            h.write(0x4d8ba0,bytes([enabled]));h.write(0x4d87d0,pack(count));h.write(0x4d87d8,pack(base));h.write(0x4d87dc,pack(base))
            for k in range(4):h.write(base+k*stride+4,bytes([255 if mask&(1<<k) else 0]))
            h.write(0x510548,bytes([iteration//7%2]));h.write(0x51054c,pack(iteration*17));h.write(0x4cf6e8,pack(1000));h.write(0x4cf70c,rng.randbytes(16))
            candidates=[k for k in range(count if count<=4 and enabled else 0) if not mask&(1<<k)];selected=candidates[0] if candidates else 0xffffffff
            def run():
                result=stream(h.memory,C.byref(clock),owner) if mode=='stream' else storage(h.memory,None,owner,scratch)
                assert result==selected,(mode,iteration,result,selected)
                if result!=0xffffffff:assert h.u32(base+result*stride+8)==owner
                assert h.read(scratch,8)==seed
                coverage['success' if result!=0xffffffff else 'failure']+=1
                return result
            h.call(mode+'_allocate',address,{},[owner],run,0xffffffff)
            assert original==native,(mode,iteration)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-slot-alloc-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_slot_alloc.c','include/halo2/network_slot_alloc.h','src/network_connection_setup.c','src/network_storage.c','tests/network_slot_alloc_oracle.py','tests/network_state_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original first-free stream/storage allocation with actual reset/clear. Full memory/DWORD returns, enable gates, signed counts, free-slot masks and owner values. Stream clock mutates pool base/count/enable and owner field; original captured slot preserved. Allocated storage starts inactive so clear performs reset without virtual releases. Not connection initialization or gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
