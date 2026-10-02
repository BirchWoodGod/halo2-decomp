#!/usr/bin/env python3
"""Complete engine endpoint-open chain, with SDK/kernel boundaries controlled."""
import argparse,ctypes as C,hashlib,json,struct,random
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from network_socket_oracle import Platform as Sockets,Allocate,Release,Shutdown,CloseHandle,Error as SocketError
from network_address_oracle import Creation,Create
from network_options_oracle import Platform as Options,Get,Set,Error
from network_bind_oracle import Binding,Bind
from network_endpoint_oracle import Operations as EndpointOps,Open,Close
Ioctl=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint32))
class Platform(C.Structure):
    _fields_=[('socket',Sockets),('creation',Creation),('options',Options),('binding',Binding),('context',C.c_void_p),('ioctl',Ioctl)]
def suite(h):
    lib=h.lib;socket=h.table;output=socket+32;rng=random.Random(0x92ae0);original=[];native=[];fault=0;option_value=0;mutation=0;incoming=[]
    def native_write(a,b):C.memmove(h.pointer+a-0x10000,b,len(b))
    def event(read,write,out,name,args):
        out.append((name,args,bytes(read(socket,8)),bytes(read(output,4)),bytes(read(0x4d8b18,2))))
        if name=='allocate':return 0 if fault&1 else socket+8*(sum(e[0]=='allocate' for e in out)-1)
        if name=='create':return 0xffffffff if fault&2 else 55
        if name=='bind':
            if mutation==1:write(0x4d8b19,b'\0')
            elif mutation==2:write(socket,struct.pack('<I',0xffffffff))
            elif mutation==3:write(socket+4,b'\x11')
        bits={'get':4,'bind':8,'ioctl':16,'set':32,'shutdown':64,'close':128}
        if name=='release':return 0 if fault&256 else 1
        return 123 if fault&bits.get(name,0) else 0
    def dispatch(name,*args):return event(h.read,native_write,native,name,args)
    def get(ctx,handle,level,option,value,length):
        result=dispatch('get',handle,level,option,value[0],length[0]);value[0]=option_value;return result
    ops=Platform(Sockets(None,Allocate(lambda ctx,*a:dispatch('allocate',*a)),Release(lambda ctx,*a:dispatch('release',*a)),Shutdown(lambda ctx,*a:dispatch('shutdown',*a)),CloseHandle(lambda ctx,*a:dispatch('close',*a)),SocketError(lambda ctx,e:dispatch('error',e))),Creation(None,Create(lambda ctx,*a:dispatch('create',*a)),Error(lambda ctx:dispatch('error',1))),Options(None,Get(get),Set(lambda ctx,handle,level,option,value,length:dispatch('set',handle,level,option,C.string_at(value,length),length)),Error(lambda ctx:dispatch('error',1))),Binding(None,Bind(lambda ctx,handle,value,length:dispatch('bind',handle,C.string_at(value,length),length)),Error(lambda ctx:dispatch('error',1))),None,Ioctl(lambda ctx,handle,command,value:dispatch('ioctl',handle,command,value[0])))
    boundaries={0x3312cc:('allocate',4),0x3312fa:('release',3),0x3cd188:('create',3),0x3cd1c3:('get',5),0x3cd1b4:('set',5),0x3cd1d2:('bind',3),0x3cd1a9:('ioctl',3),0x3cd19e:('shutdown',2),0x3cd193:('close',1),0x3cd718:('error',0),0x2d1d3e:('error',0)}
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if address==0x92ae0:incoming.append(None);return
        if address==0xb4ed0:incoming[-1]=bytes(u.mem_read(esp-28,28));return
        name,count=boundaries[address];args=list(struct.unpack('<'+'I'*count,u.mem_read(esp+4,count*4))) if count else [int(address==0x3cd718)]
        if name=='get':
            value=args[3];length=args[4];args[3]=struct.unpack('<I',u.mem_read(value,4))[0];args[4]=struct.unpack('<I',u.mem_read(length,4))[0]
        elif name=='set':args[3]=bytes(u.mem_read(args[3],args[4]))
        elif name=='bind':args[1]=bytes(u.mem_read(args[1],args[2]))
        elif name=='ioctl':args[2]=struct.unpack('<I',u.mem_read(args[2],4))[0]
        result=event(u.mem_read,u.mem_write,original,name,tuple(args))
        if name=='get':u.mem_write(value,struct.pack('<I',option_value))
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+count*4)
    for a in [*boundaries,0xb4ed0,0x92ae0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=a,end=a)
    lib.h2_network_open_endpoint_socket.argtypes=[C.POINTER(Memory),C.POINTER(Platform)]+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];lib.h2_network_open_endpoint_socket.restype=C.c_uint8
    cases=[0,*[1<<i for i in range(9)],511]+[rng.randrange(512) for _ in range(25)]
    for fault in cases:
        for special in [0,1,256]:
            for mutation in range(4):
                option_value=(fault+special+mutation)%2;active=0 if fault==511 else 1;port=rng.getrandbits(32);kind=[2,3,4][special%3]
                h.write(socket,rng.randbytes(8));h.write(output,struct.pack('<I',0xabcdef01));h.write(0x4d8b18,bytes([active,active]))
                h.u.mem_write(0x2008000-256,rng.randbytes(256));original.clear();native.clear();incoming.clear()
                workspace=(C.c_uint8*28)()
                def call():
                    if incoming and incoming[0] is not None:C.memmove(workspace,incoming[0],28)
                    return lib.h2_network_open_endpoint_socket(h.memory,C.byref(ops),kind,port,special,output,workspace)
                result=h.call('open_socket',0x92ae0,dict(eax=kind),[port,special,output],call,255)
                assert original==native,(fault,special,mutation,original,native)
                assert h.u32(output)==(socket if result else 0xabcdef01)
    endpoint=socket+0x1000
    lib.h2_network_endpoint_initialize.argtypes=[C.POINTER(Memory),C.POINTER(EndpointOps),C.c_uint32];lib.h2_network_endpoint_initialize.restype=C.c_uint8
    lib.h2_network_endpoint_close.argtypes=[C.POINTER(Memory),C.POINTER(Sockets),C.c_uint32];lib.h2_network_endpoint_close.restype=None
    call_index=0
    def native_open(ctx,kind,port,special,target):
        nonlocal call_index
        workspace=(C.c_uint8*28)()
        if incoming[call_index] is not None:C.memmove(workspace,incoming[call_index],28)
        call_index+=1
        return lib.h2_network_open_endpoint_socket(h.memory,C.byref(ops),kind,port,special,target,workspace)
    endpoint_ops=EndpointOps(None,Open(native_open),Close(lambda ctx,e:lib.h2_network_endpoint_close(h.memory,C.byref(ops.socket),e)))
    for fault in [0,1,2,8,16,32,256,511]:
        option_value=1;mutation=0;h.write(socket,rng.randbytes(64));h.write(endpoint,bytes(0x588));h.write(0x4d8b18,b'\1\1')
        original.clear();native.clear();incoming.clear();call_index=0
        h.u.mem_write(0x2008000-512,rng.randbytes(512))
        h.call('integrated_endpoint_initialize',0x92a90,dict(eax=endpoint),[],lambda:lib.h2_network_endpoint_initialize(h.memory,C.byref(endpoint_ops),endpoint),255)
        assert original==native and call_index==len(incoming)
        h.call('integrated_endpoint_close',0x92c70,{},[endpoint],lambda:lib.h2_network_endpoint_close(h.memory,C.byref(ops.socket),endpoint))
        assert original==native

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-open-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_open.c','src/network_bind.c','src/network_address.c','tests/network_open_oracle.py','tests/hash_crc_oracle.py']},scope='Complete recovered endpoint socket open chain; only SDK/kernel calls controlled. Incoming bind workspace captured from original stack. Full memory, SDK bytes/events, output publication, and returns compared. No Linux backend.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
