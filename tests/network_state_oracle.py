#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,struct,random,itertools
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
Ticks=C.CFUNCTYPE(C.c_uint32,C.c_void_p)
Provider=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32)
class Operations(C.Structure):
    _fields_=[('context',C.c_void_p),('ticks',Ticks),('provider_initialize',Provider)]
def suite(h):
    lib=h.lib;rng=random.Random(0x75970);state=h.table;config=state+0x6000;provider=config+0x200;callback=0x3000500
    original=[];native=[];switch=False;result=0
    def native_write(a,b):C.memmove(h.pointer+a-0x10000,b,len(b))
    def event(read,write,out,name,args):
        if name=='ticks':
            out.append((name,bytes(read(state+0x4f30,16)),bytes(read(0x510548,8))))
            if switch:write(0x510548,b'\1');write(0x51054c,struct.pack('<I',0xabcd1234))
            return 1000+len(out)
        out.append((name,args,bytes(read(0x477058,8))))
        write(0x47705c,b'\x55');return result
    ops=Operations(None,Ticks(lambda ctx:event(h.read,native_write,native,'ticks',())),Provider(lambda ctx,f,p:event(h.read,native_write,native,'provider',(f,p))))
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        args=() if address==0x3314b0 else (address,struct.unpack('<I',u.mem_read(esp+4,4))[0])
        value=event(u.mem_read,u.mem_write,original,'ticks' if not args else 'provider',args)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+(4 if args else 0))
    for at in [0x3314b0,callback]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    lib.h2_network_state_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*5;lib.h2_network_state_initialize.restype=C.c_uint8
    lib.h2_network_global_state_initialize.argtypes=[C.POINTER(Memory),C.c_uint32];lib.h2_network_global_state_initialize.restype=C.c_uint8
    lib.h2_network_provider_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Operations)];lib.h2_network_provider_initialize.restype=None
    for offset,override,switch,interval in itertools.product([0,1,3],[0,1,255],[False,True],[0,2000,-1,0x7fffffff]):
        state=h.table+offset;h.write(state,rng.randbytes(0x4f40));h.write(config+0xf8,struct.pack('<i',interval));h.write(0x510548,struct.pack('<II',override,0x10203040));original.clear();native.clear()
        a,b,c=[rng.getrandbits(32) for _ in range(3)]
        h.call('state_initialize',0x75970,dict(esi=state,eax=a,edx=b,ecx=c),[config],lambda:lib.h2_network_state_initialize(h.memory,C.byref(ops),state,a,b,c,config),255)
        assert original==native
        assert len(native)==(0 if override else 1 if switch else 2)
    for i in range(24):
        dependency=rng.getrandbits(32);h.write(0x4cd868,rng.randbytes(0x7e0))
        h.call('global_initialize',0x63d50,{},[dependency],lambda:lib.h2_network_global_state_initialize(h.memory,dependency),255)
    for exists,has_callback,result in itertools.product([False,True],[False,True],[0,1,128,255]):
        h.write(0x477058,struct.pack('<II',provider if exists else 0,rng.getrandbits(32)));h.write(provider+0x10,struct.pack('<I',callback if has_callback else 0));original.clear();native.clear()
        h.call('provider_initialize',0x662f0,{},[],lambda:lib.h2_network_provider_initialize(h.memory,C.byref(ops)))
        assert original==native and len(native)==int(exists and has_callback)
    lib.h2_network_auxiliary_initialize.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32]
    lib.h2_network_auxiliary_initialize.restype=C.c_uint8
    lib.h2_network_tracking_reset.argtypes=[C.POINTER(Memory)]
    lib.h2_network_tracking_reset.restype=None
    for i in range(32):
        a,b=[rng.getrandbits(32) for _ in range(2)]
        h.write(0x4cf8dc,rng.randbytes(0x98))
        h.call('auxiliary_initialize',0x7f020,dict(eax=a,ecx=b),[],
               lambda:lib.h2_network_auxiliary_initialize(h.memory,a,b),255)
        prior=rng.randbytes(0x308)
        h.write(0x4d8ba4,prior)
        h.call('tracking_reset',0x8e210,{},[],lambda:lib.h2_network_tracking_reset(h.memory))
        for j in range(32):
            address=0x4d8c28+j*0x14
            assert h.u32(address+4)==0xffffffff
            offset=address+16-0x4d8ba4
            assert h.read(address+16,4)==prior[offset:offset+4]
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-state-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_state.c','tests/network_state_oracle.py','tests/hash_crc_oracle.py']},scope='Five state setup/reset routines. Original statistics initializer executes; ticks and provider callback controlled. Full mapped memory and intermediate snapshots compared. Not complete network startup.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
