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
    stream=h.table;buffer=stream+0x200;block=stream+0x5000;out=stream+0x7000;args=stream+0x7600
    rng=random.Random(0xaf890);original=[];native=[];frames={}
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events,d,n,f,a):
        events.append((n,f,bytes(read(a,8)),bytes(read(stream,0x40))))
        assert bytes(read(d,1))==b'\0'
        write(d,b'controlled diagnostic\0')
        mode=case%7
        if mode==0:
            write(block+0x1470,struct.pack('<I',1))
            write(block+0x1474,struct.pack('<I',3))
        elif mode==1:
            write(block+0x14cc,b'\x01');write(block+0x14d0,struct.pack('<I',0xffffffff))
        elif mode==2:
            write(block+0x54,struct.pack('<I',2));write(block+0x68,struct.pack('<I',1023))
        elif mode==3:
            write(block+0x5b8,struct.pack('<I',0x8001))
        elif mode==4:
            write(block+0x624+15*0xe4,b'\x01')
            write(block+0x625+15*0xe4,b'\x00')
    cb=Format(lambda ctx,d,n,f,a:event(h.read,nw,native,d,n,f,a));ops=Ops(None,cb)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0xaf890:frames['out']=sp-0x200;u.mem_write(sp-0x200,seed[:512]);return
        if at in [0xb08ef]:frames['bytes']=bytes(u.mem_read(frames['out'],512));return
        d,n,f,a=struct.unpack('<4I',u.mem_read(sp+4,16));event(u.mem_read,u.mem_write,original,d,n,f,a)
        u.reg_write(X.UC_X86_REG_EAX,0);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0xaf890,0xb08ef,0x321980]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_parameters_encode;fn.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*4;fn.restype=None
    warnings=0;coverage={a:0 for a in [0x63690,0x7cc50,0x7c5a0,0xb2330]};isolated=set()
    def count_call(u,at,size,ctx):coverage[at]+=1
    for at in coverage:h.u.hook_add(U.UC_HOOK_CODE,count_call,begin=at,end=at)
    for case in range(2048):
        original.clear();native.clear();frames.clear();h.write(stream,rng.randbytes(0x8000))
        h.write(stream,struct.pack('<II',buffer,[0,1,4,16,128,1024,4096][case%7]));h.write(stream+0x10,struct.pack('<IB',case%32,case%11==0))
        flags=[0x10,0x1c,0x24,0x38,0x2c,0x42,0x48,0x4a,0x50,0x52,0x70,0x88,0x78,0x394,0x420,0x430,0x438,0x440,0x574,0x5b6,0x1464,0x1466,0x146a,0x1484,0x14cc]
        for i,off in enumerate(flags):h.write(block+off,bytes([case%4==0 or (case+i)%3==0]))
        h.write(block+12,struct.pack('<I',0xffffffff if case%2 else case))
        h.write(block+0x54,struct.pack('<I',case%4))
        h.write(block+0x1470,struct.pack('<I',case%4))
        h.write(block+0x8c,struct.pack('<I',case%2))
        h.write(block+0x8c+0x184,struct.pack('<I',case%2))
        h.write(block+0x444+0x44,struct.pack('<I',[0,1,2,3,4,7,8,9][case%8]))
        if case>=256:
            if case<1056:
                # Each top-level flag alone at every initial bit offset.
                index=(case-256)%25;bit=(case-256)//25
                for i,off in enumerate(flags):h.write(block+off,bytes([i==index]))
                h.write(stream+0x10,struct.pack('<I',bit));isolated.add((index,bit))
            else:
                for off in flags:h.write(block+off,b'\x01')
            for off in [0x11,0x39,0x49,0x51,0x89,0x79,0x5b7,0x1465,0x146b,0x1485]:
                h.write(block+off,bytes([(case//25)%2]))
            for off,maxlen,unit in [(0x3a0,128,1),(0x576,32,2),(0x448,32,2)]:
                h.write(block+off,b'\x61'*maxlen*unit)
                end=[None,0,1,maxlen-2,maxlen-1][case%5]
                if end is not None:h.write(block+off+end*unit,bytes(unit))
            h.write(block+0x5b8,struct.pack('<I',[0,1,0x8000,0xffff,0x10000,0xffffffff][case%6]))
            for i in range(16):
                q=block+0x624+i*0xe4
                active=case>=1056 or i==case%16
                h.write(q,bytes([active,(case+i)%2]))
                for offset,units in [(0x1c,32),(0x6c,16)]:
                    h.write(q+offset,b'\x61'*units*2)
                    end=[None,0,1,units-1][case%4]
                    if end is not None:h.write(q+offset+end*2,bytes(2))
            for off in [0x14,0x20,0x28,0x30,0x34,0x44,0x4c,0x74,0x43c,0x146c,0x1474,0x14d0]:
                h.write(block+off,struct.pack('<I',[0,1,3,15,16,31,32,4095,4096,0x80000000,0xffffffff][case%11]))
        seed=rng.randbytes(1280);argseed=rng.randbytes(8);h.write(out,seed);h.write(args,argseed)
        def run():
            fn(h.memory,C.byref(ops),stream,block,out,args)
            assert h.read(out,512)==frames['bytes'],case
            nw(out,seed);nw(args,argseed)
        h.call('parameters_encode',0xaf890,{},[stream,0x14d8,block],run,None)
        assert original==native,case;warnings+=len(original)
    assert warnings
    assert len(isolated)==800
    assert all(coverage.values()),coverage
    return warnings,{hex(k):v for k,v in coverage.items()},len(isolated)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-parameters-encode-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:warnings,coverage,isolated=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources=['src/network_parameter_lists.c','include/halo2/network_parameter_lists.h','src/network_parameter_variant.c','include/halo2/network_parameter_variant.h','src/network_parameter_record.c','include/halo2/network_parameter_record.h','src/network_parameter_block.c','include/halo2/network_parameter_block.h','src/network_parameters_encode.c','include/halo2/network_parameters_encode.h','src/bitstream_checked.c','include/halo2/bitstream_checked.h','src/format_string.c','src/bitstream.c','tests/network_parameters_encode_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),xbe_sha256=EXPECTED,comparisons=h.counts,total_comparisons=sum(h.counts.values()),diagnostic_calls=warnings,nested_calls=coverage,isolated_flag_bit_cases=isolated,source_hashes={s:sha(ROOT/s) for s in sources},scope='Original encoder, bitstream and diagnostic wrapper; controlled CRT formatting only. Full memory, diagnostic scratch and callback arguments. Unaligned bit positions, short/full buffers, sticky errors and variant branches, UTF16 boundaries, nested diagnostics and callback mutation. Valid dispatch tags only. Composed type33 encoder; not integrated or live networking.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
