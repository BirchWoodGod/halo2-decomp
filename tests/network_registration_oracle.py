#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from online_poll_oracle import Call
class Operations(C.Structure):
    _fields_=[('context',C.c_void_p),('release_address',Call),('release_key',Call)]

def suite(h):
    rng=random.Random(0xb3b10);original=[];native=[];iteration=0
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,value):
        events.append((kind,value,bytes(read(0x510580,0x280))))
        if iteration%3==0:
            write(0x5107dc,pack(123));write(0x5107e0,pack(0x55667788))
            write(0x5107e4,pack(0xffffffff if kind=='key' else 77))
        if iteration%5==0:write(0x510588,b'\xaa')
        return [0,1,0x80004005,0xffffffff][iteration%4]
    address=Call(lambda ctx,value:event(h.read,nw,native,'address',value));key=Call(lambda ctx,value:event(h.read,nw,native,'key',value));ops=Operations(None,address,key)
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);value=struct.unpack('<I',u.mem_read(esp+4,4))[0]
        result=event(u.mem_read,u.mem_write,original,'address' if at==0x3cd344 else 'key',value)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for at in [0x3cd344,0x3cd0e1]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_registration_release;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations)];fn.restype=None
    for iteration in range(384):
        original.clear();native.clear();h.write(0x510580,rng.randbytes(0x280))
        index=[0xffffffff,0,1,7,0x80000000,0xfffffffe][iteration%6]
        address_value=[0,0x11223344,0xffffffff][iteration//6%3]
        count=[0,1,2,0x7fffffff,0xffffffff][iteration//18%5]
        h.write(0x5107dc,struct.pack('<III',index,address_value,count))
        h.call('registration_release',0xb3b10,{},[],lambda:fn(h.memory,C.byref(ops)))
        assert original==native,iteration
        if index==0xffffffff:assert not native
        else:
            assert native[-1][0:2]==('key',(0x5105b8+index*0x4a)&0xffffffff)
            assert h.u32(0x5107dc)==0xffffffff and h.u32(0x5107e0)==0
        # Calling again must observe the sentinel and leave everything intact.
        original.clear();native.clear()
        h.call('registration_release_repeated',0xb3b10,{},[],lambda:fn(h.memory,C.byref(ops)))
        assert not original and not native

    remove=h.lib.h2_network_endpoint_remove_route
    remove.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];remove.restype=C.c_uint8
    endpoint=h.table
    for iteration in range(384):
        h.write(endpoint,rng.randbytes(0x588))
        count=[0,1,2,4,8,0x80000000,0xffffffff][iteration%7]
        h.write(endpoint+0x20,pack(count))
        identifiers=[rng.getrandbits(32) for i in range(8)]
        if iteration%3==0:identifiers[5]=identifiers[1]
        for i,value in enumerate(identifiers):h.write(endpoint+0x24+i*32,pack(value))
        target=identifiers[iteration//7%8] if iteration%5 else 0xffffffff
        h.call('endpoint_remove_route',0x92e00,dict(eax=endpoint,ebx=target),[],lambda:remove(h.memory,endpoint,target),255)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-registration-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_routing.c','include/halo2/network_routing.h','src/network_registration.c','include/halo2/network_registration.h','tests/network_registration_oracle.py','tests/online_poll_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original route removal (first match, swap with final entry, signed counts, AL) and registration cleanup; only two external SDK release calls controlled. Full memory and callback snapshots, captured index/wrapped key pointer, sentinel, null address, SDK errors ignored, counter underflow and callback mutations, repeated release. Raw invalid key pointers are observed at the controlled SDK boundary, not dereferenced. No complete networking shutdown or live Linux registration backend.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
