#!/usr/bin/env python3
"""File read/write/close: only SDK boundaries are controlled."""
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
from data_array_oracle import ROOT, Memory, EXPECTED

IO = C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint32))
Close = C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32)
GetError = C.CFUNCTYPE(C.c_uint32,C.c_void_p)
SetError = C.CFUNCTYPE(None,C.c_void_p,C.c_uint32)
Seek = C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class Platform(C.Structure):
    _fields_ = [('context',C.c_void_p),('read',IO),('write',IO),('close',Close),
               ('last_error',GetError),('set_error',SetError),('seek',Seek),('set_end',Close)]


def suite(h):
    lib=h.lib; rng=random.Random(0x136ca0); file=h.table
    original=[];native=[];result=0;reported=None;mutate=False
    seek_result=0;end_result=0
    def nw(a,data):C.memmove(h.pointer+a-BASE,data,len(data))
    def event(read,write,events,kind,args,initial=None):
        events.append((kind,args,initial,bytes(read(file+0x108,8))))
        if kind in ['read','write']:
            handle,buffer,count=args
            if kind=='read' and count:
                write(buffer,bytes(range(min(count,16))))
            if mutate:write(file+0x10c,struct.pack('<I',0xfffffff8))
            return result,reported if reported is not None else initial
        if kind=='set_error' and mutate:
            write(file+0x10c,struct.pack('<I',0x100+len(events)))
        if kind=='seek':
            if mutate:write(file+0x108,struct.pack('<I',0xabcdef))
            return seek_result
        if kind=='set_end':return end_result
        return result if kind=='close' else 1234

    def io(kind,handle,buffer,count,out):
        value,n=event(h.read,nw,native,kind,(handle,buffer,count),out[0]);out[0]=n;return value
    ops=Platform(None,IO(lambda ctx,a,b,c,d:io('read',a,b,c,d)),
                 IO(lambda ctx,a,b,c,d:io('write',a,b,c,d)),
                 Close(lambda ctx,a:event(h.read,nw,native,'close',(a,))),
                 GetError(lambda ctx:event(h.read,nw,native,'last_error',())),
                 SetError(lambda ctx,a:event(h.read,nw,native,'set_error',(a,))),
                 Seek(lambda ctx,a,b,c,d:event(h.read,nw,native,'seek',(a,b,c,d))),
                 Close(lambda ctx,a:event(h.read,nw,native,'set_end',(a,))))
    addresses={0x2d2241:('read',5),0x2d232e:('write',5),0x2d1f3a:('close',1),
               0x2d1d3e:('last_error',0),0x2d1d66:('set_error',1),
               0x2d2488:('seek',4),0x2d2404:('set_end',1)}
    def hook(u,address,size,context):
        kind,argc=addresses[address];esp=u.reg_read(X.UC_X86_REG_ESP)
        args=struct.unpack('<'+'I'*argc,u.mem_read(esp+4,argc*4)) if argc else ()
        if kind in ['read','write']:
            assert args[4]==0
            initial=struct.unpack('<I',u.mem_read(args[3],4))[0]
            value,n=event(u.mem_read,u.mem_write,original,kind,args[:3],initial)
            u.mem_write(args[3],struct.pack('<I',n))
        else:value=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,value)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+4+4*argc)
    for address in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    common=[C.POINTER(Memory),C.POINTER(Platform)]
    lib.h2_file_read.argtypes=common+[C.c_uint32]*3+[C.c_uint8];lib.h2_file_read.restype=C.c_uint8
    lib.h2_file_write.argtypes=common+[C.c_uint32]*3;lib.h2_file_write.restype=C.c_uint8
    lib.h2_file_close.argtypes=common+[C.c_uint32];lib.h2_file_close.restype=C.c_uint8
    for result,count,mode,mutate,suppress in itertools.product([0,1,0x80000000],[0,1,7,16],range(4),[False,True],[0,1,256,257]):
        reported=[None,0,count,count+1][mode]
        buffer=file+0x10c if mutate else file+0x400
        h.write(file,rng.randbytes(0x500));original.clear();native.clear()
        value=h.call('read',0x136ca0,dict(esi=file,ecx=buffer,edi=count),[suppress],
                     lambda:lib.h2_file_read(h.memory,C.byref(ops),file,buffer,count,suppress),255)
        assert value==int(bool(result) and (reported if reported is not None else buffer)==count)
        assert original==native
        if not value and not (suppress&255):assert [e[0] for e in native][-2:]==['last_error','set_error']
    for result,count,mode,mutate in itertools.product([0,1,0x80000000],[0,1,7,16],range(4),[False,True]):
        reported=[None,0,count,count+1][mode];buffer=file+0x400
        h.write(file,rng.randbytes(0x500));original.clear();native.clear()
        value=h.call('write',0x136d00,dict(esi=file,ecx=buffer,edi=count),[],
                     lambda:lib.h2_file_write(h.memory,C.byref(ops),file,buffer,count),255)
        assert value==int(bool(result) and (reported if reported is not None else buffer)==count)
        assert original==native
    for result,mutate,handle in itertools.product([0,1,0x80000000],[False,True],[0,1,0xffffffff]):
        h.write(file,rng.randbytes(0x110));h.write(file+0x108,struct.pack('<I',handle));original.clear();native.clear()
        value=h.call('close',0x136bb0,dict(esi=file),[],
                     lambda:lib.h2_file_close(h.memory,C.byref(ops),file),255)
        assert value==int(bool(result)) and original==native
        if value:assert h.read(file+0x108,8)==bytes(8)
    lib.h2_file_seek.argtypes=common+[C.c_uint32,C.c_uint32,C.c_uint8]
    lib.h2_file_seek.restype=C.c_uint8
    lib.h2_file_set_end.argtypes=common+[C.c_uint32,C.c_uint32]
    lib.h2_file_set_end.restype=C.c_uint8
    for seek_result,position,same,mutate,suppress in itertools.product(
            [0,7,0xffffffff],[0,7,0xffffffff],[False,True],[False,True],[0,1,256,257]):
        h.write(file,rng.randbytes(0x110))
        h.write(file+0x10c,struct.pack('<I',position if same else position^1))
        original.clear();native.clear()
        value=h.call('seek',0x136bf0,dict(esi=file,eax=position),[suppress],
                     lambda:lib.h2_file_seek(h.memory,C.byref(ops),file,position,suppress),255)
        assert value==int(same or seek_result!=0xffffffff) and original==native
        if same:assert not native
        else:assert native[0][1][1:]==(position,0,0)
    for seek_result,end_result,same,mutate in itertools.product(
            [0,7,0xffffffff],[0,1,0x80000000],[False,True],[False,True]):
        position=7
        h.write(file,rng.randbytes(0x110));h.write(file+0x10c,struct.pack('<I',position if same else 1))
        original.clear();native.clear()
        value=h.call('set_end',0x136c40,dict(esi=file,eax=position),[],
                     lambda:lib.h2_file_set_end(h.memory,C.byref(ops),file,position),255)
        assert value==int((same or seek_result!=0xffffffff) and bool(end_result))
        assert original==native
        if not same and seek_result==0xffffffff:
            assert [e[0] for e in native]==['seek','last_error','set_error','last_error','set_error']


def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/file-io-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/file_io.c','tests/file_io_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                comparisons=h.counts,total_comparisons=sum(h.counts.values()),
                source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                scope='Read/write/close/seek/set-end wrappers; SDK operations controlled. Full memory, AL, callback arguments/order and intermediate position snapshots. Includes unchanged count outputs, short I/O, callback mutations, low-byte flags, seek elision and repeated error handling. No Linux file backend or complete game file loading.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
