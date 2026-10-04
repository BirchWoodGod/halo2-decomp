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
    stream=h.table;buffer=stream+0x200;block=stream+0x5000;out=stream+0xa000;args=stream+0xb000
    rng=random.Random(0xadef0);original=[];native=[];frames={}
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events,d,n,f,a):
        events.append((n,f,bytes(read(a,8)),bytes(read(stream,0x40))))
        write(d,b'controlled diagnostic\0')
        if case%7==0:
            write(block+16,struct.pack('<H',1));write(block+18,struct.pack('<H',1))
    cb=Format(lambda ctx,d,n,f,a:event(h.read,nw,native,d,n,f,a));ops=Ops(None,cb)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0xadef0:frames['out']=sp-0xb00;u.mem_write(sp-0xb00,seed[:0xb00]);return
        if at==0xae7d7:frames['bytes']=bytes(u.mem_read(frames['out'],0xb00));return
        d,n,f,a=struct.unpack('<4I',u.mem_read(sp+4,16));event(u.mem_read,u.mem_write,original,d,n,f,a)
        u.reg_write(X.UC_X86_REG_EAX,0);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0xadef0,0xae7d7,0x321980]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_membership_encode;fn.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*4;fn.restype=None
    warnings=0
    for case in range(1024):
        original.clear();native.clear();frames.clear();h.write(stream,rng.randbytes(0xc000))
        h.write(stream,struct.pack('<II',buffer,[0,1,4,16,128,1024,8192][case%7]));h.write(stream+0x10,struct.pack('<IB',case%32,case%11==0))
        h.write(block+12,struct.pack('<I',0xffffffff if case%2 else case))
        for off in [16,18]:h.write(block+off,struct.pack('<H',[0,1,2,16,31,32,0x8000,0xffff][(case+off)%8]))
        for i in range(32):
            q=block+0x14+i*0x104
            for off in [0,2]:h.write(q+off,struct.pack('<H',[0,1,15,16,0x8000,0xffff][(case+i+off)%6]))
            for off in [0x28,0x29,0x2c,0x8e,0x98,0xb8,0xfc]:h.write(q+off,bytes([(case+i+off)%3!=0]))
            for off,units in [(0x2e,16),(0x4e,32)]:
                pos=[None,0,1,units-1][case//8%4]
                if pos is not None:h.write(q+off+pos*2,bytes(2))
            q=block+0x2094+i*0x140
            h.write(q+2,struct.pack('<H',(case+i)%4));h.write(q+20,bytes([(case+i)%3!=0]))
        h.write(block+0x4894,bytes([case%2]))
        if case>=512:
            # Isolate each field group at every bit alignment, retaining nonzero
            # backing bytes to expose absent-field writes and false-bit clears.
            group=(case-512)//32
            h.write(stream+4,struct.pack('<I',8192))
            h.write(block+16,struct.pack('<HH',int(group<10),int(10<=group<15)))
            peer=block+0x14;player=block+0x2094
            h.write(peer,struct.pack('<HH',0xffff,0xffff))
            for off in [0x28,0x29,0x2c,0x8e,0x98,0xb8,0xfc]:h.write(peer+off,b'\0')
            h.write(player,struct.pack('<HH',0,0));h.write(player+20,b'\0')
            h.write(block+0x4894,bytes([group==15]))
            if group in [0,1]:h.write(peer+group*2,struct.pack('<H',[0,15,16,0x8000][case%4]))
            if 3<=group<=9:
                h.write(peer+0x28,b'\1')
                if group>=4:h.write(peer+[0x29,0x2c,0x8e,0x98,0xb8,0xfc][group-4],b'\1')
            if group==11:h.write(player+2,struct.pack('<H',1))
            if group==12:h.write(player+2,struct.pack('<H',2))
            if group in [13,14]:
                h.write(player+2,struct.pack('<H',group-12));h.write(player+20,b'\1')
        seed=rng.randbytes(0xd00);argseed=rng.randbytes(8);h.write(out,seed);h.write(args,argseed)
        def run():
            fn(h.memory,C.byref(ops),stream,block,out,args)
            assert h.read(out,0xb00)==frames['bytes'],case
            nw(out,seed);nw(args,argseed)
        h.call('membership_encode',0xadef0,{},[stream,0x489c,block],run,None)
        assert original==native,case;warnings+=len(original)
    assert warnings
    return warnings

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-membership-encode-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:warnings=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources=['src/network_membership_encode.c','include/halo2/network_membership_encode.h','src/network_parameter_record.c','include/halo2/network_parameter_record.h','src/bitstream_checked.c','include/halo2/bitstream_checked.h','src/format_string.c','src/bitstream.c','tests/network_membership_encode_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),xbe_sha256=EXPECTED,comparisons=h.counts,total_comparisons=sum(h.counts.values()),diagnostic_calls=warnings,source_hashes={s:sha(ROOT/s) for s in sources},scope='Original encoder, bitstream and diagnostic wrapper; controlled CRT formatting only. Full memory, diagnostic scratch and callback arguments. Unaligned bit positions, short/full buffers, sticky errors and enum diagnostic boundaries. Composed membership encoder with original record bodies; signed counts and callback count mutation. Not integrated.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
