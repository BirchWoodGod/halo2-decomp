#!/usr/bin/env python3
"""Endpoint setup with controlled socket boundaries, and unmodified statistics code."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from network_state_oracle import Operations as ClockOps,Ticks,Provider
from data_array_oracle import ROOT,Memory,EXPECTED
Open=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
Close=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32)
class Operations(C.Structure):
    _fields_=[('context',C.c_void_p),('open',Open),('close_all',Close)]
def suite(h):
    lib=h.lib;endpoint=h.table;rng=random.Random(92870);mask=0;closed=0;original=[];native=[]
    h.u.reg_write(X.UC_X86_REG_MXCSR,0x1f80)
    def native_write(a,b):C.memmove(h.pointer+a-0x10000,b,len(b))
    def event(read,write,out,kind,args):
        out.append((kind,args,bytes(read(endpoint,0x588))))
        if kind=='close':write(args[0]+8,bytes([closed]));return 0
        index=[1000,1001,1005,1006].index(args[1]);success=not (mask&(1<<index))
        if success:write(args[3],struct.pack('<I',0x12340000+index))
        return 128 if success else 0
    ops=Operations(None,Open(lambda ctx,t,p,s,o:event(h.read,native_write,native,'open',(t,p,s,o))),Close(lambda ctx,e:event(h.read,native_write,native,'close',(e,))))
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if address==0x92ae0:
            args=(u.reg_read(X.UC_X86_REG_EAX),*struct.unpack('<III',u.mem_read(esp+4,12)));kind='open';purge=12
        else:args=struct.unpack('<I',u.mem_read(esp+4,4));kind='close';purge=4
        result=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for a in [0x92ae0,0x92c70]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=a,end=a)
    lib.h2_network_statistics_initialize.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_int32];lib.h2_network_statistics_initialize.restype=None
    for name in ['open','initialize']:
        f=getattr(lib,'h2_network_endpoint_'+name);f.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];f.restype=C.c_uint8
    intervals=[0,1,-1,19,20,21,-19,-20,-21,2000,0x7fffffff,-0x80000000]+[rng.randrange(-0x80000000,0x80000000) for _ in range(60)]
    for i,value in enumerate(intervals):
        target=endpoint+i%4;h.write(endpoint,rng.randbytes(0x100));padding=h.read(target+0xd4,4)
        h.call('statistics',0x92870,dict(eax=target,ecx=value&0xffffffff),[],lambda:lib.h2_network_statistics_initialize(h.memory,target,value))
        assert h.read(target+0xd4,4)==padding
    for mask in range(16):
        for closed in [0,127]:
            for name,address,reg in [('open',0x92bf0,'esi'),('initialize',0x92a90,'eax')]:
                h.write(endpoint,rng.randbytes(0x588));before=h.read(endpoint,0x588);original.clear();native.clear()
                result=h.call(name,address,{reg:endpoint},[],lambda:getattr(lib,'h2_network_endpoint_'+name)(h.memory,C.byref(ops),endpoint),255)
                assert original==native
                assert result==(1 if name=='initialize' or not mask else closed)
                assert len(native)==(4 if mask==0 else ((mask&-mask).bit_length()+1))
                if name=='initialize':
                    assert all(h.read(endpoint+0x228+i*0xd8+0xd4,4)==before[0x228+i*0xd8+0xd4:0x228+(i+1)*0xd8] for i in range(4))
    clock_original=[];clock_native=[];now=0;mutate=False
    def tick(read,write,events):
        events.append(bytes(read(endpoint,0x110)))
        if mutate:write(endpoint+0x14,struct.pack('<I',0x76543210))
        return now
    tick_cb=Ticks(lambda ctx:tick(h.read,native_write,clock_native));clock_ops=ClockOps(None,tick_cb,Provider())
    def tick_hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);value=tick(u.mem_read,u.mem_write,clock_original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    h.u.hook_add(U.UC_HOOK_CODE,tick_hook,begin=0x3314b0,end=0x3314b0)
    advance=lib.h2_network_statistics_advance;advance.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.c_uint32];advance.restype=None
    reset=lib.h2_network_samples_reset;reset.argtypes=advance.argtypes;reset.restype=None
    add=lib.h2_network_samples_add;add.argtypes=advance.argtypes+[C.c_uint32];add.restype=None
    for i in range(240):
        h.write(endpoint,rng.randbytes(0x588));period=[1,10,100,1000][i%4];last=[0,1000,0xfffff000][i//4%3];steps=[0,1,2,19,20,21,30][i//12%7]
        now=(last+steps*period+(period//2))&0xffffffff;mutate=bool(i%3==0);override=i%2
        h.write(endpoint+0x10,struct.pack('<I',last));h.write(endpoint+0x20,struct.pack('<I',period));h.write(endpoint+0x28,struct.pack('<I',i%20));h.write(0x510548,struct.pack('<II',override,now));clock_original.clear();clock_native.clear()
        h.call('statistics_advance',0x928e0,dict(esi=endpoint),[],lambda:advance(h.memory,C.byref(clock_ops),endpoint))
        assert clock_original==clock_native
    for i in range(128):
        h.write(endpoint,rng.randbytes(0x588));count=[0,1,2,20,32,0xffffffff,0x80000000][i%7];now=rng.getrandbits(32);mutate=bool(i%3==0)
        h.write(endpoint,struct.pack('<I',count));h.write(0x510548,struct.pack('<II',i%2,now));clock_original.clear();clock_native.clear()
        h.call('samples_reset',0x929d0,dict(esi=endpoint),[],lambda:reset(h.memory,C.byref(clock_ops),endpoint));assert clock_original==clock_native
    for i in range(160):
        h.write(endpoint,rng.randbytes(0x588));count=[1,2,20,32][i%4];now=rng.getrandbits(32);mutate=bool(i%3==0);value=rng.getrandbits(32)
        h.write(endpoint,struct.pack('<II',count,i%count));h.write(0x510548,struct.pack('<II',i%2,now));clock_original.clear();clock_native.clear()
        h.call('samples_add',0x92a30,dict(esi=endpoint,edi=value),[],lambda:add(h.memory,C.byref(clock_ops),endpoint,value));assert clock_original==clock_native

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-endpoint-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['include/halo2/network_endpoint.h','tests/network_state_oracle.py','src/network_endpoint.c','tests/network_endpoint_oracle.py','tests/hash_crc_oracle.py']},scope='Six routines; rolling statistics/sample rings with original instructions and controlled SDK ticks, override/mutation and wraparound; SSE default rounding; socket open/cleanup controlled. Full mapped memory and boundary event comparisons; no networking claim.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
