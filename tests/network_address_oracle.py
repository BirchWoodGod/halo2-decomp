#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct,itertools
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from network_options_oracle import Platform as Options,Get,Set,Error
Create=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class Creation(C.Structure):
    _fields_=[('context',C.c_void_p),('create',Create),('last_error',Error)]
def suite(h):
    lib=h.lib;rng=random.Random(5470);source=h.table+32;length=h.table+160;socket=h.table+256
    for name in ['to_sockaddr','from_sockaddr']:
        f=getattr(lib,'h2_network_address_'+name);f.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32,C.c_uint32];f.restype=C.c_uint8
    for repeat,kind,offset,alias in itertools.product(range(4),[0,4,16,0xffff,8],[-8,0,4,8,40],[False,True]):
        h.write(h.table,rng.randbytes(512));h.write(source+18,struct.pack('<H',kind))
        target=source+offset;size_address=source+16 if alias else length
        h.call('to_sockaddr',0xb5470,dict(esi=source,ecx=target,edi=size_address),[],lambda:lib.h2_network_address_to_sockaddr(h.memory,source,target,size_address),255)
        h.write(h.table,rng.randbytes(512));size={4:16,16:28}.get(kind,kind)
        h.call('from_sockaddr',0xb5560,dict(esi=source,ecx=target,edx=size),[],lambda:lib.h2_network_address_from_sockaddr(h.memory,source,size,target),255)
    registered=lib.h2_network_address_registered_ipv4
    registered.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];registered.restype=C.c_uint8
    for i in range(384):
        h.write(h.table,rng.randbytes(512));kind=[0,4,16,0xffff,8,0x8000][i%6]
        h.write(source+18,struct.pack('<H',kind))
        value=[0,1,0x00123456,0x01123456,0xff123456,0x7f000001][i//6%6]
        h.write(source,struct.pack('<I',value))
        if i%11==0:h.write(source,bytes(16))
        target=source+[-4,0,1,4,16,64][i//7%6];address=0 if i%19==0 else source
        h.call('registered_ipv4',0x7aec0,dict(ecx=address,edi=target),[],lambda:registered(h.memory,address,target),255)
    original=[];native=[];fail=False;option_value=0
    def snapshot(read):return bytes(read(socket,8))
    def create(ctx,family,type,protocol):native.append(('create',family,type,protocol,snapshot(h.read)));return 0xffffffff if fail else 55
    def error(ctx):native.append(('error',snapshot(h.read)))
    def get(ctx,handle,level,option,value,size):
        native.append(('get',handle,level,option,value[0],size[0],snapshot(h.read)));value[0]=option_value;return int(fail)
    creation=Creation(None,Create(create),Error(error));options=Options(None,Get(get),Set(),Error(error))
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if address==0x3cd188:
            args=struct.unpack('<III',u.mem_read(esp+4,12));original.append(('create',*args,snapshot(u.mem_read)));result=0xffffffff if fail else 55;count=3
        elif address==0x3cd1c3:
            handle,level,option,value,length_ptr=struct.unpack('<5I',u.mem_read(esp+4,20))
            original.append(('get',handle,level,option,struct.unpack('<I',u.mem_read(value,4))[0],struct.unpack('<I',u.mem_read(length_ptr,4))[0],snapshot(u.mem_read)))
            u.mem_write(value,struct.pack('<I',option_value));result=int(fail);count=5
        else:original.append(('error',snapshot(u.mem_read)));result=0;count=0
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+4*count)
    for a in [0x3cd188,0x3cd1c3,0x3cd718]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=a,end=a)
    lib.h2_network_socket_ensure_handle.argtypes=[C.POINTER(Memory),C.POINTER(Creation),C.POINTER(Options),C.c_uint32,C.c_uint32];lib.h2_network_socket_ensure_handle.restype=C.c_uint8
    for kind,size,existing,fail,active,option_value in itertools.product([2,3,4,0xffff],[4,16,0],[0xffffffff,17],[False,True],[0,1],[0,1]):
        h.write(socket,struct.pack('<IHH',existing,0xa503,kind));h.write(source+18,struct.pack('<H',size));h.write(0x4d8b18,bytes([active,active]))
        original.clear();native.clear()
        result=h.call('ensure_handle',0xb53e0,dict(esi=socket),[source],lambda:lib.h2_network_socket_ensure_handle(h.memory,C.byref(creation),C.byref(options),socket,source),255)
        assert original==native and result==int(existing!=0xffffffff or not fail)
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-address-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_address.c','tests/network_address_oracle.py','tests/hash_crc_oracle.py']},scope='Address conversions including registered IPv4 filtering/output and aliases, unmodified x86; handle helper uses actual option wrapper with SDK calls controlled. Preserved bytes, overlap and full mapped memory compared. No OS networking.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
