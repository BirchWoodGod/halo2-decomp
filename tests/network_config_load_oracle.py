#!/usr/bin/env python3
"""Full original configuration loader; SDK boundaries only are controlled."""
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
import zlib
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE, STACK
from file_io_oracle import IO, Close, GetError, SetError
from file_metadata_oracle import Attributes, Metadata
from file_open_oracle import Open, OpenPlatform
from data_array_oracle import ROOT, Memory, EXPECTED


def suite(h):
    lib=h.lib;rng=random.Random(0x7fa40);workspace=h.table
    original_file=STACK+0x7ee8
    original=[];native=[];scenario='';payload=b''
    def nw(a,data):C.memmove(h.pointer+a-BASE,data,len(data))
    def event(read,write,events,file,kind,args):
        events.append((kind,args,bytes(read(file,0x110)),bytes(read(0x4cf970,28))))
        if kind=='attributes':return 0xffffffff if scenario=='missing' else 0
        if kind=='metadata':return 0 if scenario=='metadata_failure' else 1
        if kind=='open':return 0xffffffff if scenario=='open_failure' else 0x1234
        if kind=='read':
            assert args==(0x1234,0x4cf970,0x8e4c),args
            amount=0x8e4c
            if scenario in ['short_read','read_failure']:amount-=7
            write(0x4cf970,payload[:amount])
            return int(scenario!='read_failure'),amount
        if kind=='close':return int(scenario!='close_failure')
        if kind=='last_error':return 2 if scenario=='missing' else 5
        return 0
    def metadata(ctx,path,level,out):
        result=event(h.read,nw,native,workspace+4,'metadata',(C.string_at(path,256),level))
        size=0x8e4b if scenario=='wrong_size' else 0x8e4c
        C.memmove(out,bytes(32)+struct.pack('<I',size),36)
        return result
    def read(ctx,handle,buffer,count,out):
        result,amount=event(h.read,nw,native,workspace+4,'read',(handle,buffer,count))
        out[0]=amount;return result
    ops=OpenPlatform()
    callbacks={}
    callbacks['attributes']=Attributes(lambda ctx,path:event(h.read,nw,native,workspace+4,'attributes',(C.string_at(path,256),)))
    callbacks['metadata']=Metadata(metadata)
    callbacks['open']=Open(lambda ctx,path,*args:event(h.read,nw,native,workspace+4,'open',(C.string_at(path,256),*args)))
    callbacks['read']=IO(read)
    callbacks['close']=Close(lambda ctx,handle:event(h.read,nw,native,workspace+4,'close',(handle,)))
    callbacks['last_error']=GetError(lambda ctx:event(h.read,nw,native,workspace+4,'last_error',()))
    callbacks['set_error']=SetError(lambda ctx,error:event(h.read,nw,native,workspace+4,'set_error',(error,)))
    # Retain callbacks explicitly: inherited ctypes field indices can collide
    # in its internal reference-keeping dictionary.
    for name,callback in callbacks.items():setattr(ops,name,callback)
    addresses={0x2d6a9e:('attributes',1),0x2d6ae9:('metadata',3),0x2d2750:('open',7),
               0x2d2241:('read',5),0x2d1f3a:('close',1),0x2d1d3e:('last_error',0),0x2d1d66:('set_error',1)}
    def hook(u,address,size,ctx):
        kind,argc=addresses[address];esp=u.reg_read(X.UC_X86_REG_ESP)
        args=struct.unpack('<'+'I'*argc,u.mem_read(esp+4,4*argc)) if argc else ()
        if kind in ['attributes','metadata','open']:
            values=(bytes(u.mem_read(args[0],256)),)
            if kind=='metadata':values+=(args[1],)
            if kind=='open':values+=args[1:]
        elif kind=='read':values=args[:3]
        else:values=args
        value=event(u.mem_read,u.mem_write,original,original_file,kind,values)
        if kind=='metadata':
            size=0x8e4b if scenario=='wrong_size' else 0x8e4c
            u.mem_write(args[2],bytes(32)+struct.pack('<I',size))
        if kind=='read':
            assert args[4]==0
            value,amount=value;u.mem_write(args[3],struct.pack('<I',amount))
        u.reg_write(X.UC_X86_REG_EAX,value)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+4+4*argc)
    for address in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    lib.h2_network_config_load.argtypes=[C.POINTER(Memory),C.POINTER(OpenPlatform),C.c_uint32]
    lib.h2_network_config_load.restype=C.c_uint8
    scenarios=['valid','missing','metadata_failure','wrong_size','open_failure','read_failure',
               'short_read','bad_crc','bad_version','bad_fields','close_failure']
    for n in [0,1,7,350]:
        for scenario in scenarios:
            data=bytearray(rng.randbytes(0x8e4c))
            struct.pack_into('<7I',data,0,8,0,n,*([0xffffffff]*4))
            for i in range(n):
                p=28+i*0x68;data[p:p+4]=i.to_bytes(4,'big')
                struct.pack_into('<I',data,p+8,i*4);data[p+0x4c:p+0x54]=bytes(8)
            if scenario=='bad_version':struct.pack_into('<I',data,0,7)
            if scenario=='bad_fields':
                if n:data[28+0x4c]=254
                else:struct.pack_into('<I',data,8,351)
            struct.pack_into('<I',data,4,zlib.crc32(data[8:])^0xffffffff)
            if scenario=='bad_crc':data[4]^=1
            payload=bytes(data)
            h.write(0x4cf970,rng.randbytes(0x8e4c))
            h.write(0x55e755,b'\0')
            prior=rng.randbytes(0x114);h.write(workspace,prior)
            original.clear();native.clear()
            def load():
                value=lib.h2_network_config_load(h.memory,C.byref(ops),workspace)
                # Only the dedicated temporary workspace is excluded from the
                # persistent-memory comparison. Compare its actual file bytes
                # and initialized scratch word with the original stack first.
                assert h.read(workspace+4,0x110)==bytes(h.u.mem_read(original_file,0x110))
                if scenario!='missing':
                    assert h.read(workspace,4)==bytes(h.u.mem_read(original_file-4,4))
                nw(workspace,prior)
                return value
            result=h.call('configuration_load',0x7fa40,{},[],load,255)
            assert original==native
            assert result==int(scenario in ['valid','close_failure'])
            kinds=[e[0] for e in native]
            assert ('close' in kinds)==(scenario not in ['missing','metadata_failure','wrong_size','open_failure'])


def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/network-config-load-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_config.c','src/file_io.c','src/file_path.c','src/crc.c',
             'tests/network_config_load_oracle.py','tests/file_open_oracle.py',
             'tests/file_metadata_oracle.py','tests/file_io_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                comparisons=h.counts,total_comparisons=sum(h.counts.values()),
                source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                scope='Complete original loader with all engine/CRT callees intact; SDK calls controlled. Persistent guest memory and AL compared; temporary native workspace compared separately against original stack locals, then excluded. Covers existence/size/open/read/CRC/validation failures and close behavior. No Linux backend or complete startup.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
