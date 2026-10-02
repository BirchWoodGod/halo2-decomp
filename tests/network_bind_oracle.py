#!/usr/bin/env python3
"""Bind wrapper and recovered callees; preserve the complete incoming local buffer."""
import argparse,ctypes as C,hashlib,json,struct,itertools,random
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from network_address_oracle import Creation,Create
from network_options_oracle import Platform as Options,Get,Set,Error
Bind=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint8),C.c_uint32)
class Binding(C.Structure):
    _fields_=[('context',C.c_void_p),('bind',Bind),('last_error',Error)]
def suite(h):
    lib=h.lib;socket=h.table;address=socket+32;original=[];native=[];create_result=55;bind_status=0;option_value=0;rng=random.Random(0xb4ed0)
    def error(ctx):native.append(('error',h.read(socket,8)))
    def create(ctx,family,type,protocol):native.append(('create',family,type,protocol,h.read(socket,8)));return create_result
    def get(ctx,handle,level,option,value,length):
        native.append(('get',handle,level,option,value[0],length[0]));value[0]=option_value;return 0
    def bind(ctx,handle,data,length):native.append(('bind',handle,C.string_at(data,length),length,h.read(socket,8)));return bind_status
    creation=Creation(None,Create(create),Error(error));options=Options(None,Get(get),Set(),Error(error));binding=Binding(None,Bind(bind),Error(error))
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x3cd188:
            args=struct.unpack('<III',u.mem_read(esp+4,12));original.append(('create',*args,bytes(u.mem_read(socket,8))));result=create_result;count=3
        elif at==0x3cd1c3:
            handle,level,option,value,length=struct.unpack('<5I',u.mem_read(esp+4,20))
            original.append(('get',handle,level,option,struct.unpack('<I',u.mem_read(value,4))[0],struct.unpack('<I',u.mem_read(length,4))[0]));u.mem_write(value,struct.pack('<I',option_value));result=0;count=5
        elif at==0x3cd1d2:
            handle,data,length=struct.unpack('<III',u.mem_read(esp+4,12));original.append(('bind',handle,bytes(u.mem_read(data,length)),length,bytes(u.mem_read(socket,8))));result=bind_status;count=3
        else:original.append(('error',bytes(u.mem_read(socket,8))));result=0;count=0
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+count*4)
    for at in [0x3cd188,0x3cd1c3,0x3cd1d2,0x3cd718]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    lib.h2_network_socket_bind.argtypes=[C.POINTER(Memory),C.POINTER(Creation),C.POINTER(Options),C.POINTER(Binding),C.c_uint32,C.c_uint32,C.POINTER(C.c_uint8)];lib.h2_network_socket_bind.restype=C.c_uint8
    for width,flags,existing,create_result,bind_status,option_value in itertools.product([0,4,16,0xffff],[(0,1),(1,0),(1,1),(255,255)],[17,0xffffffff],[55,0xffffffff],[0,123],[0,1]):
        h.write(socket,struct.pack('<IHH',existing,0xa503,3));h.write(address,rng.randbytes(20));h.write(address+18,struct.pack('<H',width));h.write(0x4d8b18,bytes(flags))
        initial=rng.randbytes(28);workspace=(C.c_uint8*28).from_buffer_copy(initial)
        h.u.mem_write(0x2008000-28,initial);original.clear();native.clear()
        result=h.call('bind',0xb4ed0,dict(eax=address),[socket],lambda:lib.h2_network_socket_bind(h.memory,C.byref(creation),C.byref(options),C.byref(binding),socket,address,workspace),255)
        assert original==native,(width,flags,existing,create_result,bind_status,option_value)
        assert bytes(workspace)==bytes(h.u.mem_read(0x2008000-28,28))
        expected=all(flags) and width in [4,16] and (existing!=0xffffffff or create_result!=0xffffffff) and bind_status==0
        assert result==int(expected)
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-bind-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_bind.c','tests/network_bind_oracle.py','tests/hash_crc_oracle.py']},scope='Bind wrapper executes recovered conversion, handle and option helpers. SDK create/get/bind/error controlled; all temporary address bytes and guest memory compared. No Linux backend.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
