#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x88110);connections=h.table;streams=connections+0x1000;storage=connections+0x4000;local=connections+0xe200;packet=connections+0xe300
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    original=[];native=[];coverage={'ticks':0,'dispose':0,'success':0,'failure':0};iteration=0;current=connections
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events):
        events.append((bytes(read(connections,0xe140)),bytes(read(0x4d87d0,16))))
        if events is original:coverage['ticks']+=1
        if iteration%3==0:write(current+0x48,pack(0x38));write(0x4d87d0,pack(0))
        elif iteration%5==0:write(current+0x48,pack(0x20))
        return 100+iteration
    tick=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,tick,Provider())
    def hook(u,at,size,ctx):
        nonlocal current
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x88110:current=u.reg_read(X.UC_X86_REG_ESI);return
        if at==0x886e0:coverage['dispose']+=1;return
        result=event(u.mem_read,u.mem_write,original);u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x88110,0x886e0,0x3314b0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    initialize=h.lib.h2_network_connection_initialize;initialize.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_void_p]*4+[C.c_uint32]*10+[C.POINTER(C.c_uint8)];initialize.restype=C.c_uint8
    allocate=h.lib.h2_network_connection_allocate;allocate.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_void_p]*4+[C.c_uint32]*5+[C.POINTER(C.c_uint8)];allocate.restype=C.c_uint32
    for mode in ['initialize','allocate']:
        for iteration in range(1024):
            original.clear();native.clear();h.write(connections,rng.randbytes(0xe140));h.write(local,rng.randbytes(20));before=h.read(local,20)
            enabled=iteration//8%3;count=[0,1,2,4,0xffffffff,0x80000000][iteration//24%6]
            h.write(0x4d8ba0,bytes([enabled]));h.write(0x4d87d0,pack(count));h.write(0x4d87d4,pack(connections));h.write(0x4d87d8,pack(streams));h.write(0x4d87dc,pack(storage))
            h.write(0x510548,bytes([iteration//8%2]));h.write(0x51054c,pack(iteration));h.write(0x4cf6e8,pack(1000));h.write(0x4cf70c,rng.randbytes(16))
            for k in range(4):
                c=connections+k*0xf8;h.write(c+0x10,pack(0xffffffff)*2);h.write(c+0x54,pack(0 if k>=iteration//144%5 else 2))
                h.write(streams+k*0x97c+4,bytes([1 if (iteration//2+k)%5==0 else 0]));h.write(storage+k*0x2850+4,bytes([1 if (iteration//3+k)%5==0 else 0]))
            index=iteration%4;current=connections+index*0xf8;flags=(iteration%8)*8;label=rng.getrandbits(32)
            # The direct constructor receives caller-owned pointers; none are invoked.
            args=[flags,0x528000,0x528b28,0x529188,0x4cf6d4]
            def run():
                prefix=(h.memory,C.byref(clock),None,None,None,None)
                if mode=='initialize':result=initialize(*prefix,connections+index*0xf8,index,*args,local,packet,local+12,(C.c_uint8*28)())
                else:result=allocate(*prefix,label,flags,local,packet,local+12,(C.c_uint8*28)())
                coverage['failure' if (result==0 if mode=='initialize' else result==0xffffffff) else 'success']+=1
                assert h.read(local,20)==before
                return result
            h.call(mode,0x88110 if mode=='initialize' else 0x82060,dict(esi=connections+index*0xf8,edx=index) if mode=='initialize' else {},args if mode=='initialize' else [label,flags],run,255 if mode=='initialize' else 0xffffffff)
            assert original==native,(mode,iteration)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-allocate-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_connection_allocate.c','include/halo2/network_connection_allocate.h','src/network_slot_alloc.c','src/network_connection_setup.c','src/network_storage.c','src/network_connection.c','tests/network_connection_allocate_oracle.py','tests/network_state_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original connection initialize/allocate and actual stream/storage allocation, reset and failure disposal. Full guest memory/returns, signed count and enable gates, occupied entries, flags8/16/32 combinations, clock mutations of flags/count. Incoming slot indices -1, allocated storage inactive: no queued releases or close packets. Not admission or gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
