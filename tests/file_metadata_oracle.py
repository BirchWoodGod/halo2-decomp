#!/usr/bin/env python3
"""Original existence/size wrappers and path resolver; SDK queries controlled."""
import argparse
import ctypes as C
import hashlib
import itertools
import json
import random
import struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from file_io_oracle import Platform, GetError, SetError
from data_array_oracle import ROOT, Memory, EXPECTED

Attributes=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.POINTER(C.c_uint8))
Metadata=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(C.c_uint8))
class QueryPlatform(Platform):
    _fields_=[('attributes',Attributes),('metadata',Metadata)]


def suite(h):
    lib=h.lib;rng=random.Random(0x136e90);file=h.table
    original=[];native=[];result=0;errors=(0,0,0);information=bytes(36)
    def event(events,kind,args):
        events.append((kind,args))
        if kind in ['attributes','metadata']:return result
        if kind=='last_error':return errors[sum(e[0]=='last_error' for e in events)-1]
        return 0
    def metadata(ctx,path,level,out):
        value=event(native,'metadata',(C.string_at(path,256),level))
        C.memmove(out,information,36)
        return value
    ops=QueryPlatform()
    ops.last_error=GetError(lambda ctx:event(native,'last_error',()))
    ops.set_error=SetError(lambda ctx,error:event(native,'set_error',(error,)))
    ops.attributes=Attributes(lambda ctx,path:event(native,'attributes',(C.string_at(path,256),)))
    ops.metadata=Metadata(metadata)
    addresses={0x2d6a9e:('attributes',1),0x2d6ae9:('metadata',3),
               0x2d1d3e:('last_error',0),0x2d1d66:('set_error',1)}
    def hook(u,address,size,ctx):
        kind,argc=addresses[address];esp=u.reg_read(X.UC_X86_REG_ESP)
        args=struct.unpack('<'+'I'*argc,u.mem_read(esp+4,4*argc)) if argc else ()
        if kind=='attributes':values=(bytes(u.mem_read(args[0],256)),)
        elif kind=='metadata':
            values=(bytes(u.mem_read(args[0],256)),args[1])
            u.mem_write(args[2],information)
        else:values=args
        value=event(original,kind,values)
        u.reg_write(X.UC_X86_REG_EAX,value)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+4+argc*4)
    for address in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    lib.h2_file_exists.argtypes=[C.POINTER(Memory),C.POINTER(QueryPlatform),C.c_uint32]
    lib.h2_file_exists.restype=C.c_uint8
    lib.h2_file_size.argtypes=[C.POINTER(Memory),C.POINTER(QueryPlatform),C.c_uint32,C.c_uint32]
    lib.h2_file_size.restype=C.c_uint8
    paths=[b'',b'config.bin',b'd:\\data\\config',b'Z:\\config',b'1:\\config',b'x'*255,b'x'*300]
    for path,result,errors in itertools.product(paths,[0,1,0x80000000,0xffffffff],
                                               [(2,9,9),(9,3,9),(9,9,2),(3,2,9)]):
        h.write(file,rng.randbytes(0x500));h.write(file+8,path+b'\0')
        original.clear();native.clear()
        value=h.call('exists',0x1368f0,{},[file],
                     lambda:lib.h2_file_exists(h.memory,C.byref(ops),file),255)
        assert value==int(result!=0xffffffff) and original==native
        expected_queries=0 if value else 1 if errors[0]==2 else 2 if errors[1]==3 else 3
        assert sum(e[0]=='last_error' for e in native)==expected_queries
        assert sum(e[0]=='set_error' for e in native)==int(expected_queries==3)
    for path,result,low,alias in itertools.product(paths,[0,1,0x80000000],
                                                  [0,1,0x8e4c,0xffffffff],[False,True]):
        output=file+8 if alias else file+0x400
        errors=(0,0,0);information=rng.randbytes(32)+struct.pack('<I',low)
        h.write(file,rng.randbytes(0x500));h.write(file+8,path+b'\0');before=h.u32(output)
        original.clear();native.clear()
        value=h.call('size',0x136e90,{},[file,output],
                     lambda:lib.h2_file_size(h.memory,C.byref(ops),file,output),255)
        assert value==int(bool(result)) and original==native
        assert h.u32(output)==(low if result else before)
        assert native[0][1][1]==0


def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/file-metadata-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/file_io.c','src/file_path.c','tests/file_metadata_oracle.py',
             'tests/file_io_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                comparisons=h.counts,total_comparisons=sum(h.counts.values()),
                source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                scope='Existence and low-size metadata queries; original path resolver and CRT calls intact, SDK queries controlled. Full guest memory, path-buffer bytes, return values and repeated error queries compared. No Linux backend or file opening.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
