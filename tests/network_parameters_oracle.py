#!/usr/bin/env python3
"""Parameter constructors: original instructions, no controlled call boundaries."""
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    lib=h.lib;rng=random.Random(0x70190);base=h.table
    lib.h2_network_parameter_set_initialize.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*8;lib.h2_network_parameter_set_initialize.restype=None
    for name in ['parameter5_initialize','parameter6_initialize','parameter_runtime_initialize']:
        f=getattr(lib,'h2_network_'+name);f.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];f.restype=None
    for iteration in range(60):
        set_address=base+iteration%4;p5=base+0x100+iteration%4;p6=base+0x400+iteration%4;seed=base+0x2000
        if iteration%3==0:seed=p6+0x968
        h.write(base,rng.randbytes(0x2200));h.write(0x477088,rng.randbytes(0xe0))
        values=[rng.getrandbits(32) for _ in range(7)]
        h.call('parameter_set',0x6de50,dict(eax=set_address),values,lambda:lib.h2_network_parameter_set_initialize(h.memory,set_address,*values))
        h.call('parameter5',0x6f090,dict(eax=p5,edx=set_address),[],lambda:lib.h2_network_parameter5_initialize(h.memory,p5,set_address))
        h.write(0x4e7408,struct.pack('<I',seed))
        bounds=[0,1,32767,0xffff,0x8000,0x12340003]
        first=bounds[iteration%6];second=bounds[(iteration//6)%6]
        h.write(0x4ce1dc,struct.pack('<I',first));h.write(0x4ce1d4,struct.pack('<I',second))
        initial=h.u32(seed+4)
        h.call('parameter6',0x70190,dict(eax=p6,ecx=set_address),[],lambda:lib.h2_network_parameter6_initialize(h.memory,p6,set_address))
        assert h.u32(set_address+0x18)==p5 and h.u32(set_address+0x1c)==p6
        if seed!=p6+0x968:
            expected=initial
            for _ in range(2):expected=(expected*0x19660d+0x3c6ef35f)&0xffffffff
            assert h.u32(seed+4)==expected
        dependency,owner=values[:2]
        h.call('runtime',0x72c80,dict(edx=dependency,esi=owner),[],lambda:lib.h2_network_parameter_runtime_initialize(h.memory,dependency,owner))

    lib.h2_network_parameters_initialize.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*6
    lib.h2_network_parameters_initialize.restype=C.c_uint8
    objects=[0x52738c,0x52739c,0x5273bc,0x5273d0,0x5273e8,
             0x5273f8,0x527500,0x527f98,0x527fb8,0x527fd8]
    for iteration in range(60):
        session=0x52e0f8+(iteration%3)*0x78b8
        h.write(session,rng.randbytes(0x78b8))
        h.write(0x527330,rng.randbytes(0xcd0))
        h.write(0x477088,rng.randbytes(0x150))
        seed=base+0x2000
        h.write(0x4e7408,struct.pack('<I',seed))
        initial=rng.getrandbits(32)
        h.write(seed+4,struct.pack('<I',initial))
        h.write(0x4ce1dc,struct.pack('<I',bounds[iteration%6]))
        h.write(0x4ce1d4,struct.pack('<I',bounds[(iteration//6)%6]))
        ecx,edx,a,b,c=[rng.getrandbits(32) for _ in range(5)]
        def initialize():
            return lib.h2_network_parameters_initialize(h.memory,session,ecx,edx,a,b,c)
        h.call('parameter_startup',0x58ee0,dict(eax=session,ecx=ecx,edx=edx),
               [a,b,c],initialize,mask=0xff)
        assert h.u32(session+0x78a8)==0x527fe8
        assert h.u32(0x527fec)==session
        assert [h.u32(0x527338+i*4) for i in range(10)]==objects
        for index,p in enumerate(objects):
            assert h.u32(p+4)==index and h.u32(p+8)==0x527334
        assert [h.u32(0x527334+i) for i in [0x40,0x44,0x2c,0x30,0x34,0x38,0x3c]]==[a,b,edx,ecx,c,session,0x527fe8]
        expected=initial
        for _ in range(2):expected=(expected*0x19660d+0x3c6ef35f)&0xffffffff
        assert h.u32(seed+4)==expected
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-parameter-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_parameters.c','tests/network_parameters_oracle.py','tests/hash_crc_oracle.py']},scope='Four constructors and enclosing parameter setup, unmodified original instructions; full mapped-memory comparison. Signed random bounds, aliased seed/output, ten registry links and preserved bytes. No complete network startup or parameter state-machine claim.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
