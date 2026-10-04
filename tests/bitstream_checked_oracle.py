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
    stream=h.table;buffer=stream+0x200;block=stream+0x1000;out=stream+0x1100;args=stream+0x1300
    rng=random.Random(0x1947e0);original=[];native=[];frames={}
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events,d,n,f,a):
        events.append((n,f,bytes(read(a,8)),bytes(read(stream,0x40))))
        write(d,b'controlled diagnostic\0')
        if case%3==0:
            write(stream+0x10,struct.pack('<I',31))
            write(stream+4,struct.pack('<I',4))
    cb=Format(lambda ctx,d,n,f,a:event(h.read,nw,native,d,n,f,a));ops=Ops(None,cb)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x1947e0:frames['out']=sp-0x100;u.mem_write(sp-0x100,seed);return
        if at==0x194821:frames['bytes']=bytes(u.mem_read(frames['out'],256));return
        d,n,f,a=struct.unpack('<4I',u.mem_read(sp+4,16));event(u.mem_read,u.mem_write,original,d,n,f,a)
        u.reg_write(X.UC_X86_REG_EAX,0);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x1947e0,0x194821,0x321980]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_bitstream_write_checked;fn.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*5;fn.restype=None
    warnings=0
    for case in range(2048):
        original.clear();native.clear();frames.clear();h.write(stream,rng.randbytes(0x1400))
        h.write(stream,struct.pack('<II',buffer,[0,1,4,16,60,64,128][case%7]));h.write(stream+0x10,struct.pack('<IB',case%32,case%11==0))
        width=[0,1,2,3,4,5,7,15,16,30,31,32,33,63,0x80000000,0xffffffff][case%16]
        limit=1<<(width&31)
        value=[0,1,limit-1,limit, (limit+1)&0xffffffff,0x7fffffff,0x80000000,0xffffffff][case//16%8]
        seed=rng.randbytes(256);argseed=rng.randbytes(8);h.write(out,seed);h.write(args,argseed)
        def run():
            fn(h.memory,C.byref(ops),stream,value,width,out,args)
            assert h.read(out,256)==frames['bytes'],case
            nw(out,seed);nw(args,argseed)
        h.call('bitstream_write_checked',0x1947e0,dict(ebx=value,edi=width),[stream],run,None)
        assert original==native,case;warnings+=len(original)
    assert warnings
    return warnings

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/bitstream-checked-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:warnings=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources=['src/bitstream_checked.c','include/halo2/bitstream_checked.h','src/format_string.c','src/bitstream.c','tests/bitstream_checked_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),xbe_sha256=EXPECTED,comparisons=h.counts,total_comparisons=sum(h.counts.values()),diagnostic_calls=warnings,source_hashes={s:sha(ROOT/s) for s in sources},scope='Original checked writer, bitstream and diagnostic wrapper; controlled CRT formatting only. Full memory, diagnostic scratch and callback arguments. Unaligned bit positions, short/full buffers, sticky errors and width/value diagnostic boundaries, signed width comparison, x86 shift masking, callback stream mutations. Not full type33 encoder.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
