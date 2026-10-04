#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
Format=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class Ops(C.Structure):_fields_=[('context',C.c_void_p),('format',Format)]
def suite(h):
    stream=h.table;buffer=stream+0x200;block=stream+0x1000;out=stream+0x1200;args=stream+0x1500
    rng=random.Random(0x7c5a0);original=[];native=[];frames={}
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events,d,n,f,a):
        events.append((n,f,bytes(read(a,8)),bytes(read(stream,0x40))))
        write(d,b'controlled diagnostic\0')
        if case%7==0:write(block+0x81,b'\3')
    cb=Format(lambda ctx,d,n,f,a:event(h.read,nw,native,d,n,f,a));ops=Ops(None,cb)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x7c5a0:frames['out']=sp-0x100;u.mem_write(sp-0x100,seed[:256]);return
        if at==0x7ee10:frames['nested']=sp-0x100;u.mem_write(sp-0x100,seed[256:]);return
        if at==0x7ef8d:frames['nested_bytes']=bytes(u.mem_read(frames['nested'],256));return
        if at==0x7ca60:frames['bytes']=bytes(u.mem_read(frames['out'],256));return
        d,n,f,a=struct.unpack('<4I',u.mem_read(sp+4,16));event(u.mem_read,u.mem_write,original,d,n,f,a)
        u.reg_write(X.UC_X86_REG_EAX,0);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x7ee10,0x7ef8d,0x7c5a0,0x7ca60,0x321980]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_parameter_record_write;fn.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*4;fn.restype=None
    warnings=0
    for case in range(512):
        original.clear();native.clear();frames.clear();h.write(stream,rng.randbytes(0x1600))
        h.write(stream,struct.pack('<II',buffer,[0,1,4,16,60,64,128][case%7]));h.write(stream+0x10,struct.pack('<IB',case%32,case%11==0))
        # Arbitrary UTF16, early terminators, maximum-length names and optional IDs.
        pos=[None,0,1,15,30,31][case%6]
        if pos is not None:h.write(block+pos*2,bytes(2))
        pos=[None,0,1,14,15][case//6%5]
        if pos is not None:h.write(block+0x50+pos*2,bytes(2))
        if case%3==0:h.write(block+0x70,h.read(0x440070,12))
        for off in [0x7c,0x7d,0x7e,0x7f,0x80,0x81]:
            h.write(block+off,bytes([[0,1,3,7,15,16,127,128,254,255][(case+off)%10]]))
        h.write(block+0x84,struct.pack('<I',[0,1,15,16,0xffffffff][case%5]))
        for off in [0x88,0x8a]:h.write(block+off,struct.pack('<H',[0,127,128,32768,65535][(case+off)%5]))
        h.write(block+0x8c,struct.pack('<I',[0,0x3fffffff,0x40000000,0xffffffff][case%4]))
        seed=rng.randbytes(512);argseed=rng.randbytes(8);h.write(out,seed);h.write(args,argseed)
        def run():
            fn(h.memory,C.byref(ops),stream,block,out,args)
            assert h.read(out,256)==frames['bytes'],case
            assert h.read(out+256,256)==frames['nested_bytes'],case
            nw(out,seed);nw(args,argseed)
        h.call('parameter_record_write',0x7c5a0,dict(eax=stream),[block],run,None)
        assert original==native,case;warnings+=len(original)
    assert warnings
    return warnings

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-parameter-record-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:warnings=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources=['src/network_parameter_record.c','include/halo2/network_parameter_record.h','src/format_string.c','src/bitstream.c','tests/network_parameter_record_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),xbe_sha256=EXPECTED,comparisons=h.counts,total_comparisons=sum(h.counts.values()),diagnostic_calls=warnings,source_hashes={s:sha(ROOT/s) for s in sources},scope='Original encoder, bitstream and diagnostic wrapper; controlled CRT formatting only. Full memory, diagnostic scratch and callback arguments. Unaligned bit positions, short/full buffers, sticky errors, UTF16 boundaries, optional signed fields, nested diagnostics and callback mutation. Not full type33 encoder.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
