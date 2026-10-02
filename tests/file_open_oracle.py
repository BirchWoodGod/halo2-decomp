#!/usr/bin/env python3
"""File opening against original instructions, with SDK calls controlled."""
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
from file_io_oracle import GetError, SetError, Seek, Close
from file_metadata_oracle import QueryPlatform
from data_array_oracle import ROOT, Memory, EXPECTED

Open=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.POINTER(C.c_uint8),*[C.c_uint32]*6)
class OpenPlatform(QueryPlatform):
    _fields_=[('open',Open)]


def suite(h):
    lib=h.lib;rng=random.Random(0x136970);file=h.table;output=file+0x400
    original=[];native=[];handle=0x12345678;position=17;error=0;close_result=1;mutate=False
    def nw(a,data):C.memmove(h.pointer+a-BASE,data,len(data))
    def event(read,write,events,kind,args):
        events.append((kind,args,bytes(read(file+0x108,8)),bytes(read(output,4))))
        if kind=='open':return handle
        if kind=='seek':
            if mutate:write(file+0x108,struct.pack('<I',0xaabbccdd))
            return position
        if kind=='close':
            if mutate:write(file+0x10c,struct.pack('<I',0xdeadbeef))
            return close_result
        if kind=='last_error':return error if sum(e[0]=='last_error' for e in events)==1 else 999
        return 0
    ops=OpenPlatform()
    ops.open=Open(lambda ctx,path,*args:event(h.read,nw,native,'open',(C.string_at(path,256),*args)))
    ops.seek=Seek(lambda ctx,*args:event(h.read,nw,native,'seek',args))
    ops.close=Close(lambda ctx,a:event(h.read,nw,native,'close',(a,)))
    ops.last_error=GetError(lambda ctx:event(h.read,nw,native,'last_error',()))
    ops.set_error=SetError(lambda ctx,a:event(h.read,nw,native,'set_error',(a,)))
    addresses={0x2d2750:('open',7),0x2d2488:('seek',4),0x2d1f3a:('close',1),
               0x2d1d3e:('last_error',0),0x2d1d66:('set_error',1)}
    def hook(u,address,size,ctx):
        kind,argc=addresses[address];esp=u.reg_read(X.UC_X86_REG_ESP)
        args=struct.unpack('<'+'I'*argc,u.mem_read(esp+4,argc*4)) if argc else ()
        if kind=='open':args=(bytes(u.mem_read(args[0],256)),*args[1:])
        value=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,value)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+4+argc*4)
    for address in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    lib.h2_file_open.argtypes=[C.POINTER(Memory),C.POINTER(OpenPlatform)]+[C.c_uint32]*3
    lib.h2_file_open.restype=C.c_uint8
    paths=[b'config.bin',b'd:\\maps\\test',b'Z:\\test',b'x'*300]
    def run(flags,path):
        h.write(file,rng.randbytes(0x500));h.write(file+8,path+b'\0')
        original.clear();native.clear()
        value=h.call('open',0x136970,dict(ebx=file),[flags,output],
                     lambda:lib.h2_file_open(h.memory,C.byref(ops),file,flags,output),255)
        assert original==native
        assert value==int(handle!=0xffffffff and (not flags&4 or position!=0xffffffff))
        args=native[0][1]
        assert args[1]==((0x80000000 if flags&1 else 0)|(0x40000000 if flags&2 else 0))
        assert args[2]==int(not(flags&2) or bool(flags&8))
        expected_attributes=0x80
        for bit,attribute in [(0x20,0x100),(0x40,0x4000000),(0x80,0x10000000),(0x100,0x8000000)]:
            if flags&bit:expected_attributes=attribute
        assert args[3:]==(0,3,expected_attributes,0)
        if output==file+0x400:
            expected_error={2:1,3:3,5:2,15:4,32:5}.get(error,6) if handle==0xffffffff else 0
            assert h.u32(output)==expected_error
        if handle!=0xffffffff and flags&4 and position==0xffffffff:
            assert h.read(file+0x108,8)==bytes(8)
            assert [e[0] for e in native][:3]==['open','seek','close']
    for flags in range(512):run(flags,paths[flags%4])
    handle=0xffffffff
    for error,flags in itertools.product(list(range(132))+[0xffffffff,0x80000000],[1,0x11]):
        run(flags,paths[error%4])
    for handle,position,close_result,mutate,flags in itertools.product(
            [0,0x80000000],[0,0xffffffff],[0,1],[False,True],[4,0x14,0xffffffff]):
        run(flags,paths[flags%4])
    for output,handle,position in itertools.product([file+8,file+0x108,file+0x10c],
                                                   [0x1234,0xffffffff],[0,0xffffffff]):
        error=5;mutate=True;run(4,b'config.bin')


def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/file-open-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/file_io.c','src/file_path.c','tests/file_open_oracle.py',
             'tests/file_metadata_oracle.py','tests/file_io_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                comparisons=h.counts,total_comparisons=sum(h.counts.values()),
                source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                scope='Open wrapper and original path resolver/CRT execute unchanged; SDK calls controlled. All low-nine-bit flag combinations, error mapping, failed initial seek cleanup, callback snapshots and output aliasing. No Linux file backend.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
