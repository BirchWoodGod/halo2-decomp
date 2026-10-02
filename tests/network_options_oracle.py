#!/usr/bin/env python3
"""Original option mapping/get/set, with SDK boundary values and failures controlled."""
import argparse,ctypes as C,hashlib,json,struct,itertools,random
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
Get=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32))
Set=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint8),C.c_uint32)
Error=C.CFUNCTYPE(None,C.c_void_p)
class Platform(C.Structure):
    _fields_=[('context',C.c_void_p),('get',Get),('set',Set),('last_error',Error)]
def suite(h):
    lib=h.lib;socket=h.table;payload=socket+16;original=[];native=[];status=0;write_output=False;rng=random.Random(0xb4e00)
    def native_get(ctx,handle,level,option,value,length):
        native.append(('get',handle,level,option,value[0],length[0]))
        if write_output:value[0]=0xdeadbeef;length[0]=2
        return status
    def native_set(ctx,handle,level,option,value,length):
        native.append(('set',handle,level,option,C.string_at(value,length),length));return status
    ops=Platform(None,Get(native_get),Set(native_set),Error(lambda ctx:native.append(('error',))))
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if address==0x3cd718:original.append(('error',));count=0
        else:
            handle,level,option,data,last=struct.unpack('<5I',u.mem_read(esp+4,20));count=5
            if address==0x3cd1c3:
                original.append(('get',handle,level,option,struct.unpack('<I',u.mem_read(data,4))[0],struct.unpack('<I',u.mem_read(last,4))[0]))
                if write_output:u.mem_write(data,struct.pack('<I',0xdeadbeef));u.mem_write(last,struct.pack('<I',2))
            else:original.append(('set',handle,level,option,bytes(u.mem_read(data,last)),last))
        u.reg_write(X.UC_X86_REG_EAX,status);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+count*4)
    for address in [0x3cd1c3,0x3cd1b4,0x3cd718]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    lib.h2_network_option_code.argtypes=[C.c_uint32];lib.h2_network_option_code.restype=C.c_uint32
    lib.h2_network_socket_get_option.argtypes=[C.POINTER(Memory),C.POINTER(Platform),C.c_uint32,C.c_uint32];lib.h2_network_socket_get_option.restype=C.c_uint32
    lib.h2_network_socket_set_option.argtypes=[C.POINTER(Memory),C.POINTER(Platform),C.c_uint32,C.c_uint32,C.c_uint32];lib.h2_network_socket_set_option.restype=C.c_uint8
    options=[0,1,2,3,4,5,6,0xffff,0x8000,0x10000,0x12340005,0xffffffff]
    for option in options+[rng.getrandbits(32) for _ in range(40)]:
        value=h.call('code',0xb4da0,{},[option],lambda:lib.h2_network_option_code(option),0xffffffff)
        codes=[4,0x80,0x20,0x1001,0x1002,0x4001]
        assert value==(codes[option&0xffff] if option&0xffff<6 else 0xffffffff)
    for flags,handle,option,status,write_output in itertools.product([(0,1),(1,0),(1,1),(255,255)],[17,0xffffffff],options,[0,0xffffffff],[False,True]):
        h.write(0x4d8b18,bytes(flags));h.write(socket,struct.pack('<I',handle));h.write(payload,b'\x12\x34\x56\x78')
        original.clear();native.clear()
        result=h.call('get',0xb4e00,{},[socket,option],lambda:lib.h2_network_socket_get_option(h.memory,C.byref(ops),socket,option),0xffffffff)
        assert original==native
        invoked=all(flags) and handle!=0xffffffff and (option&0xffff)<6
        assert result==(0xdeadbeef if invoked and write_output else 0)
        original.clear();native.clear();value=payload if option&0xffff==5 else 0x87654321
        result=h.call('set',0xb4e70,dict(esi=option),[socket,value],lambda:lib.h2_network_socket_set_option(h.memory,C.byref(ops),socket,option,value),255)
        assert original==native and result==int(invoked and status==0)
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-option-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_options.c','tests/network_options_oracle.py','tests/hash_crc_oracle.py']},scope='Three option routines; get/set/error SDK boundaries controlled. Full mapped memory and option bytes compared. No OS networking implementation.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
