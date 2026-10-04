#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import STOP
P=lambda n:struct.pack('<I',n&0xffffffff)
F=lambda n:struct.pack('<f',n)
Power=C.CFUNCTYPE(None,C.c_void_p,C.c_float,C.c_float,C.POINTER(C.c_longdouble))
class Math(C.Structure):_fields_=[('context',C.c_void_p),('power',Power)]
def suite(h):
    f=h.lib.h2_network_session_candidate_preferred;f.argtypes=[C.POINTER(Memory),C.POINTER(Math)]+[C.c_uint32]*4;f.restype=C.c_uint8
    rng=random.Random(0x619b0);session=h.table;stub=STOP+0x600;data=STOP+0x800;original=[];native=[];power=0.;coverage={'math':0,'integer':0,'true':0,'false':0}
    cb=Power(lambda ctx,b,e,out:(native.append((F(b),F(e))),setattr(out.contents,'value',power)))
    math=Math(None,cb)
    # CRT boundary only: consume ST0 exponent/ST1 base, install controlled ST0.
    code=b'\xdd\x1d'+P(data)+b'\xdd\x1d'+P(data+8)+b'\xdd\x05'+P(data+16)+b'\xc3'
    h.u.mem_write(stub,code)
    def hook(u,addr,size,ctx):
        if addr==0x372d48:u.reg_write(X.UC_X86_REG_EIP,stub);return
        e,b=struct.unpack('<dd',u.mem_read(data,16));original.append((F(b),F(e)));u.mem_write(data+16,struct.pack('<d',power))
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x372d48,end=0x372d48);h.u.hook_add(U.UC_HOOK_CODE,hook,begin=stub+12,end=stub+12)
    for case in range(1024):
        h.write(session,rng.randbytes(0x400));a=session+0x10c;b=session
        mask=rng.getrandbits(32);h.write(a+0x9c,P(mask));h.write(b+0x9c,P(mask if case%4 else rng.getrandbits(32)))
        priority=rng.getrandbits(32);h.write(a+0xf8,P(priority));h.write(b+0xf8,P(priority if case%3 else rng.getrandbits(32)))
        for p in [a,b]:
            h.write(p+0x94,P(rng.getrandbits(32)));h.write(p+0xa4,P(rng.getrandbits(32)))
        index=case%17;h.write(0x4ce0c4+index*4,P(rng.getrandbits(32)))
        for p,v in [(0x4ce074,[0.,1e-6,-0.5,1.][case%4]),(0x4ce078,[0.,1e-5,0.5,-1.][case//4%4]),(0x4ce07c,[0.,0.5,1.,2.][case%4]),(0x45dbd8,0.),(0x44ae90,[0.,0.3,-1.,100.][case%4])]:h.write(p,F(v))
        power=[0.,0.25,1.,2.,-0.5,65536.][case%6];original.clear();native.clear()
        h.u.reg_write(X.UC_X86_REG_FPCW,0x37f);h.u.reg_write(X.UC_X86_REG_MXCSR,0x1f80)
        result=h.call('candidate_preferred',0x619b0,dict(ecx=session,edx=1,eax=0),[index],lambda:f(h.memory,C.byref(math),session,1,0,index),255)
        assert original==native,(case,'power arguments');coverage['math' if original else 'integer']+=1;coverage['true' if result else 'false']+=1
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_session_candidate_rank_preview.so');p.add_argument('--report',default='analysis/network-session-candidate-rank-preview.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_session_candidate_rank.c','include/halo2/network_session_candidate_rank.h','src/network_peer_mask_count.c','tests/network_session_candidate_rank_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original ranking engine instructions and population count; CRT power boundary controlled with exact finite results. Full memory, AL, stack purge, power arguments, signed ranking/rate caps and wrapped differences, SSE rounding. Does not validate native CRT power, exceptional FP inputs or live handoff.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
