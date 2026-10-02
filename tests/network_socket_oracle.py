#!/usr/bin/env python3
"""Socket records and endpoint cleanup with only SDK calls controlled."""
import argparse,ctypes as C,hashlib,json,random,struct,itertools
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from network_endpoint_oracle import Operations as EndpointOps,Open,Close
Allocate=C.CFUNCTYPE(C.c_uint32,C.c_void_p,*([C.c_uint32]*4))
Release=C.CFUNCTYPE(C.c_uint32,C.c_void_p,*([C.c_uint32]*3))
Shutdown=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32)
CloseHandle=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32)
Error=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32)
class Platform(C.Structure):
    _fields_=[('context',C.c_void_p),('allocate',Allocate),('release',Release),('shutdown',Shutdown),('close',CloseHandle),('last_error',Error)]
def suite(h):
    lib=h.lib;endpoint=h.table;sockets=endpoint+0x100;rng=random.Random(0xb4f50);original=[];native=[];failure=0;mutate=False
    def native_write(a,b):C.memmove(h.pointer+a-0x10000,b,len(b))
    def event(read,write,out,kind,args):
        out.append((kind,args,bytes(read(endpoint,0x140)),bytes(read(0x4d8b18,2))))
        if kind=='allocate':return 0 if failure&1 else sockets
        if kind=='shutdown':
            if mutate:
                for i in range(4):
                    at=sockets+i*8
                    if struct.unpack('<I',read(at,4))[0]==args[0]:write(at,struct.pack('<I',(args[0]+77)&0xffffffff))
                write(0x4d8b19,b'\0')
            return 0xffffffff if failure&2 else 0
        if kind=='close':return 123 if failure&4 else 0
        if kind=='release':return 0 if failure&8 else 1
        return 0
    platform=Platform(None,Allocate(lambda ctx,*a:event(h.read,native_write,native,'allocate',a)),Release(lambda ctx,*a:event(h.read,native_write,native,'release',a)),Shutdown(lambda ctx,*a:event(h.read,native_write,native,'shutdown',a)),CloseHandle(lambda ctx,*a:event(h.read,native_write,native,'close',a)),Error(lambda ctx,e:event(h.read,native_write,native,'error',(e,))))
    boundaries={0x3312cc:('allocate',4),0x3312fa:('release',3),0x3cd19e:('shutdown',2),0x3cd193:('close',1),0x3cd718:('error',0),0x2d1d3e:('error',0)}
    def hook(u,address,size,ctx):
        kind,count=boundaries[address];esp=u.reg_read(X.UC_X86_REG_ESP)
        args=struct.unpack('<'+'I'*count,u.mem_read(esp+4,count*4)) if count else (int(address==0x3cd718),)
        result=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+count*4)
    for address in boundaries:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    for name in ['socket_create','socket_close','endpoint_close']:
        f=getattr(lib,'h2_network_'+name);f.argtypes=[C.POINTER(Memory),C.POINTER(Platform),C.c_uint32];f.restype=C.c_uint32 if name=='socket_create' else None
    def reset(initialized,active,flags,handle):
        h.write(endpoint,rng.randbytes(0x140));h.write(0x4d8b18,bytes([initialized,active]))
        for i in range(4):
            h.write(sockets+i*8,struct.pack('<IHH',handle,flags,0x1234+i))
            h.write(endpoint+0xc+i*4,struct.pack('<I',sockets+i*8 if i!=2 else 0))
        original.clear();native.clear()
    for initialized,active,failure in itertools.product([0,1,255],[0,1,255],[0,1]):
        for kind in [0,3,0x1234,0xffffffff]:
            reset(initialized,active,0xffff,10)
            h.call('create',0xb4d50,{},[kind],lambda:lib.h2_network_socket_create(h.memory,C.byref(platform),kind),0xffffffff)
            assert original==native
    for initialized,active,failure,flags,mutate in itertools.product([0,1],[0,1],range(0,16,2),[0,1,0xffff],[False,True]):
        for name,address,regs,args in [('socket_close',0xb4f50,dict(esi=sockets),[]),('endpoint_close',0x92c70,{},[endpoint])]:
            reset(initialized,active,flags,0xffffffff if failure==14 else 42)
            target=sockets if name=='socket_close' else endpoint
            h.call(name,address,regs,args,lambda:getattr(lib,'h2_network_'+name)(h.memory,C.byref(platform),target))
            assert original==native,(name,initialized,active,failure,flags,mutate)
    # Run real endpoint open/initialize plus recovered cleanup after partial opens.
    lib.h2_network_endpoint_initialize.argtypes=[C.POINTER(Memory),C.POINTER(EndpointOps),C.c_uint32];lib.h2_network_endpoint_initialize.restype=C.c_uint8
    fail_at=0
    def open_boundary(read,write,out,args):
        index=[1000,1001,1005,1006].index(args[1]);out.append(('open',args))
        if index==fail_at:return 0
        write(args[3],struct.pack('<I',sockets+index*8));return 1
    endpoint_ops=EndpointOps(None,Open(lambda ctx,*a:open_boundary(h.read,native_write,native,a)),Close(lambda ctx,e:lib.h2_network_endpoint_close(h.memory,C.byref(platform),e)))
    def open_hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);args=(u.reg_read(X.UC_X86_REG_EAX),*struct.unpack('<III',u.mem_read(esp+4,12)))
        result=open_boundary(u.mem_read,u.mem_write,original,args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+16)
    h.u.hook_add(U.UC_HOOK_CODE,open_hook,begin=0x92ae0,end=0x92ae0)
    for fail_at,failure in itertools.product(range(4),[0,14]):
        mutate=False;reset(1,1,1,42);h.write(endpoint+0xc,bytes(16))
        h.call('integrated_initialize_failure',0x92a90,dict(eax=endpoint),[],lambda:lib.h2_network_endpoint_initialize(h.memory,C.byref(endpoint_ops),endpoint),255)
        assert original==native
        assert h.read(endpoint+8,1)==b'\0' and h.read(endpoint+0xc,16)==bytes(16)
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-socket-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_socket.c','tests/network_socket_oracle.py','tests/hash_crc_oracle.py']},scope='Socket create/close and endpoint cleanup. SDK/kernel allocation, shutdown, close and error APIs controlled. Partial-open integration executes recovered cleanup. Not OS networking.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
