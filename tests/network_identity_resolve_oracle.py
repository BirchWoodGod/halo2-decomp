#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STACK
from data_array_oracle import ROOT,Memory,EXPECTED
Resolve=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class Ops(C.Structure):
    _fields_=[('context',C.c_void_p),('resolve',Resolve),('scratch32',C.c_uint32)]
def suite(h):
    rng=random.Random(0x7ab60);a=h.table;identity=a+0x100;out=a+0x200;scratch=a+0x400
    original=[];native=[];calls=0
    def put(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,ip,ident,metadata):
        events.append((ip,ident,bytes(read(metadata,20)),bytes(read(a,0x300))))
        write(ident,identity_data);write(metadata,key+metadata_data)
        if mutate:
            write(0x4cf7d4+match*32,b'\x01')
            write(0x4cf7d4+match*32+8,key)
        return error
    cb=Resolve(lambda ctx,ip,ident,metadata:event(h.read,put,native,ip,ident,metadata));ops=Ops(None,cb,scratch)
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);args=struct.unpack('<III',u.mem_read(esp+4,12))
        result=event(u.mem_read,u.mem_write,original,*args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+16)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3cd32d,end=0x3cd32d)
    fn=h.lib.h2_network_identity_resolve;fn.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*6;fn.restype=C.c_uint8
    for case in range(1024):
        h.write(a,rng.randbytes(0x500));h.write(0x4cf7d4,rng.randbytes(256))
        width=[4,4,4,4,16,0xffff,0][case%7];ip=[0,1,0x123456,0x7f000001,0xff000001][case%5]
        h.write(a,struct.pack('<I',ip));h.write(a+18,struct.pack('<H',width))
        direct=1 if case%4==0 else 0;error=[0,0,1,0x80004005][case%4];mutate=case%3==0;match=case%8
        identity_data=rng.randbytes(36);key=rng.randbytes(8);metadata_data=rng.randbytes(12)
        for i in range(8):
            h.write(0x4cf7d4+i*32,bytes([1 if i%3 else 0]))
            h.write(0x4cf7d4+i*32+8,key if i==match and case%2 else rng.randbytes(8))
        index4=0 if case%8==0 else out
        key8=0 if case%8==1 else [out+4,out,identity,a][case%4]
        metadata16=0 if case%8==2 else [out+12,out+2,identity+4,a+4][case%4]
        seed=h.read(scratch,32);h.u.mem_write(STACK+0x8000-32,seed)
        original.clear();native.clear()
        def run():
            result=fn(h.memory,C.byref(ops),a,direct,index4,key8,metadata16,identity)
            assert h.read(scratch,28)==bytes(h.u.mem_read(STACK+0x8000-32,28)),case
            put(scratch,seed);return result
        h.call('resolve-identity',0x7ab60,dict(ecx=a,edx=direct),[index4,key8,metadata16,identity],run,mask=255)
        assert original==native,(case,original,native);calls+=len(original)
    assert calls>0
    return calls
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-identity-resolve-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:calls=suite(h)
    finally:h.close()
    sources=['src/network_identity_resolve.c','include/halo2/network_identity_resolve.h','src/network_address.c','tests/network_identity_resolve_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),sdk_calls=calls,
        source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original identity resolution and registered IPv4 extraction. SDK resolution controlled; full memory, normalized local scratch, SDK arguments/snapshots, invalid addresses, direct identities, SDK failures with output writes, registration matching and callback mutation, optional and overlapping outputs.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
