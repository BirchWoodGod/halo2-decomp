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
    rng=random.Random(0x7cc50);original=[];native=[];frames={}
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events,d,n,f,a):
        events.append((n,f,bytes(read(a,8)),bytes(read(stream,0x40))))
        assert bytes(read(d,1))==b'\0'
        write(d,b'controlled diagnostic\0')
        if case<1024 and case%7==0:
            write(block+0x44,struct.pack('<I',9))
            write(block+0xf4,struct.pack('<I',3))
    cb=Format(lambda ctx,d,n,f,a:event(h.read,nw,native,d,n,f,a));ops=Ops(None,cb)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x7cc50:frames['out']=sp-0x100;u.mem_write(sp-0x100,seed[:256]);return
        if at in [0x7d2cc,0x7d308,0x7d436]:frames['bytes']=bytes(u.mem_read(frames['out'],256));return
        d,n,f,a=struct.unpack('<4I',u.mem_read(sp+4,16));event(u.mem_read,u.mem_write,original,d,n,f,a)
        u.reg_write(X.UC_X86_REG_EAX,0);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x7cc50,0x7d2cc,0x7d308,0x7d436,0x321980]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_parameter_variant_write;fn.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*4;fn.restype=None
    warnings=0
    for case in range(2048):
        original.clear();native.clear();frames.clear();h.write(stream,rng.randbytes(0x1600))
        h.write(stream,struct.pack('<II',buffer,[0,1,4,16,60,64,128][case%7]));h.write(stream+0x10,struct.pack('<IB',case%32,case%11==0))
        tag=[0,1,2,3,4,7,8,9][case%8]
        h.write(block+0x44,struct.pack('<I',tag))
        h.write(block,struct.pack('<H',[0,1,2,65535][case//8%4]))
        pos=[None,0,1,15,30,31][case//32%6]
        if pos is not None:h.write(block+4+pos*2,bytes(2))
        if case%5==0:
            h.write(block+0x48,bytes(0xc4))
        if case>=1024:
            # Every valid tag at all 32 alignments, with in-range and overflowing
            # numeric boundaries. Disable callback mutations for these cases.
            level=(case-1024)//256
            tag=[0,1,2,3,4,7,8,9][(case-1024)//32%8]
            h.write(stream+4,struct.pack('<I',512));h.write(block,bytes(0x10c))
            h.write(block+0x44,struct.pack('<I',tag))
            def value(bits):return [0,(1<<bits)-1,1<<bits,0xffffffff][level]
            def dword(off,bits):h.write(block+off,struct.pack('<I',value(bits)))
            def signedword(off,bits):h.write(block+off,struct.pack('<H',value(bits)&0xffff))
            signedword(0,1);h.write(block+3,bytes([255,126,127,128][level:level+1]))
            for off,bits in [(0x48,15),(0x4c,3),(0x50,16),(0x54,16),(0x58,2),(0x74,5),(0x78,5),(0x7c,16),(0x80,16),(0x84,16),(0x88,2),(0xa4,2),(0xa8,2),(0xac,16),(0xb4,4)]:dword(off,bits)
            for i,bits in enumerate([2,3,3,3,3,3,3,3,5,2,5,5]):h.write(block+0xcc+i,bytes([value(bits)&255]))
            if tag in [1,9]:
                for off,bits in [(0xf0,8),(0xf4,16),(0xf8,2),(0xfc,1),(0x100,2),(0x104,2)]:dword(off,bits)
                if tag==9:signedword(0x108,16);signedword(0x10a,16)
            elif tag in [2,3]:
                dword(0xf0,3)
                if tag==3:
                    for off,bits in [(0xf4,2),(0xf6,1),(0xf8,2),(0xfa,2)]:signedword(off,bits)
            elif tag==4:dword(0xf0,5);signedword(0xf4,16)
            elif tag==7:dword(0xf0,7);signedword(0xf4,2)
            elif tag==8:
                for off,bits in [(0xf0,4),(0xf2,16),(0xf4,16)]:signedword(off,bits)
        # Diagnostics may change a later field and the final variant dispatch.
        seed=rng.randbytes(512);argseed=rng.randbytes(8);h.write(out,seed);h.write(args,argseed)
        def run():
            fn(h.memory,C.byref(ops),stream,block,out,args)
            assert h.read(out,256)==frames['bytes'],case
            nw(out,seed);nw(args,argseed)
        h.call('parameter_variant_write',0x7cc50,{},[stream,block],run,None)
        assert original==native,case;warnings+=len(original)
    assert warnings
    return warnings

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-parameter-variant-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:warnings=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources=['src/network_parameter_variant.c','include/halo2/network_parameter_variant.h','src/bitstream_checked.c','include/halo2/bitstream_checked.h','src/format_string.c','src/bitstream.c','tests/network_parameter_variant_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),xbe_sha256=EXPECTED,comparisons=h.counts,total_comparisons=sum(h.counts.values()),diagnostic_calls=warnings,source_hashes={s:sha(ROOT/s) for s in sources},scope='Original encoder, bitstream and diagnostic wrapper; controlled CRT formatting only. Full memory, diagnostic scratch and callback arguments. Unaligned bit positions, short/full buffers, sticky errors and variant branches, UTF16 boundaries, nested diagnostics and callback mutation. Valid dispatch tags only. Not full type33 encoder.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
