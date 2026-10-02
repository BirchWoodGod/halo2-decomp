#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations as Clock,Ticks,Provider
from network_send_oracle import Ops as SendOps
from message_dispatch_oracle import NativeCodec,Platform
Lookup=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
Release=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class Operations(C.Structure):
    _fields_=[('context',C.c_void_p),('lookup',Lookup),('release',Release)]

def suite(h):
    rng=random.Random(0x94bf0);storage=h.table+0x1000;owner=storage+0x4000;other=owner+0x20;objects=owner+0x100;vtable=owner+0x200;scratch=owner+0x300
    connection=storage+0x6000;small=storage+0x6400;endpoint=storage+0x7800;writer=storage+0x8000;table=storage+0x9000;message=storage+0xa000;packet=storage+0xb000;message_incoming=bytes(12)
    lookup_at=0x3000800;release_at=0x3000900;original=[];native=[];frame={};iteration=0;incoming=bytes(8)
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,function,obj,handle,argument,local):
        events.append((kind,function,obj,handle,argument-local if kind=='lookup' else argument,bytes(read(storage,0x2850)),bytes(read(owner,0x40)),bytes(read(local,8)),bytes(read(0x4d87f8,4))))
        if kind=='lookup':
            if wrapper and iteration%11==0:write(connection+0x10,pack(0xffffffff))
            if iteration%2:write(argument,pack(0x87654321))
            if iteration%3==0:write(0x4d87f8,pack(other))
            if iteration%7==0:
                # Shorten both queues during the first callback; loop bounds
                # are reloaded, current entry and handle remain captured.
                for off in [0,0x181c]:
                    first=struct.unpack('<I',read(storage+off+0x1c,4))[0];write(storage+off+0x18,pack(first+1))
            return 255 if iteration%4 else 0
        if iteration%3==0:write(0x4d87f8,pack(owner))
        if iteration%5==0:
            write(other+4,pack(0));write(owner+4,pack(0xffffffff))
        return 0
    lookup=Lookup(lambda ctx,f,o,v,out:event(h.read,nw,native,'lookup',f,o,v,out,scratch))
    release=Release(lambda ctx,f,o,v,arg:event(h.read,nw,native,'release',f,o,v,arg,scratch));ops=Operations(None,lookup,release)
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x94bf0:frame['local']=esp-8;u.mem_write(esp-8,incoming);return
        if at==0x88650:frame['message']=esp-12;u.mem_write(esp-12,message_incoming);return
        if at==0x886d5:frame['message_bytes']=bytes(u.mem_read(frame['message'],12));return
        handle,arg=struct.unpack('<II',u.mem_read(esp+4,8));kind='lookup' if at==lookup_at else 'release'
        result=event(u.mem_read,u.mem_write,original,kind,at,u.reg_read(X.UC_X86_REG_ECX),handle,arg,frame['local'])
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+12)
    for at in [0x94bf0,0x88650,0x886d5,lookup_at,release_at]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    clear=h.lib.h2_network_storage_clear;clear.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];clear.restype=None
    clock=Clock(None,Ticks(),Provider());send=SendOps();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    dispose=h.lib.h2_network_connection_dispose
    dispose.argtypes=[C.POINTER(Memory),C.POINTER(Clock),C.POINTER(SendOps),C.POINTER(Platform),C.c_void_p,C.POINTER(Operations)]+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];dispose.restype=None
    for wrapper in [False,True]:
        for iteration in range(512):
            original.clear();native.clear();frame.clear();incoming=rng.randbytes(8);h.write(scratch,incoming);h.write(storage,rng.randbytes(0x2850))
            h.write(storage+4,bytes([0 if iteration%13==0 else 255]));h.write(0x4d87f8,pack(owner))
            h.write(owner,struct.pack('<II',objects,iteration));h.write(other,struct.pack('<II',objects+4,0xffffffff))
            h.write(objects,struct.pack('<II',vtable,vtable));h.write(vtable,struct.pack('<II',release_at,lookup_at))
            for queue,off,stride in [(0,0,12),(1,0x181c,8)]:
                first=[0,0xfffffffc,0x7ffffffa,99][iteration%4];n=(iteration//4+queue)%5
                if iteration%17==0:n=-1
                origin=[0,3,7][iteration%3]
                if iteration%19==0:n=1;origin=0xfffffff8
                capacity=0xfffffff8 if iteration%23==0 else 8
                h.write(storage+off+0x14,struct.pack('<III',capacity,(first+n)&0xffffffff,first))
                h.write(storage+off+0x24,struct.pack('<II',origin,1))
                for i in range(8):
                    entry=storage+off+0x2c+i*stride
                    h.write(entry+1,bytes([(iteration+i)%256]));h.write(entry+4,pack(0 if (iteration+i+queue)%4==0 else 0x12340000+queue*16+i))
            if wrapper:
                h.write(connection,rng.randbytes(0xf8));h.write(small,rng.randbytes(0x97c));h.write(endpoint,bytes(0x588));h.write(writer,bytes(0x700))
                h.write(connection,struct.pack('<II',endpoint,writer));h.write(connection+0x3c,bytes(4))
                h.write(connection+0x54,pack([0,2,3,5,0xffffffff,0x80000000][iteration%6]))
                h.write(connection+0x10,struct.pack('<II',0xffffffff if iteration%5==0 else 0,0xffffffff if iteration%7==0 else 0))
                h.write(connection+0x82,struct.pack('<H',4));h.write(writer+8,struct.pack('<II',endpoint,table))
                h.write(0x4d87dc,pack(storage));h.write(0x4d87d8,pack(small));message_incoming=rng.randbytes(12);h.write(message,message_incoming)
            def run():
                if wrapper:dispose(h.memory,C.byref(clock),C.byref(send),C.byref(codec),None,C.byref(ops),connection,message,packet,scratch,(C.c_uint8*28)())
                else:clear(h.memory,C.byref(ops),storage,scratch)
                expected=bytes(h.u.mem_read(frame['local'],8)) if 'local' in frame else incoming
                assert h.read(scratch,8)==expected,(wrapper,iteration)
                if wrapper:
                    expected=frame.get('message_bytes',message_incoming)
                    assert h.read(message,12)==expected,iteration
                    nw(message,message_incoming)
                nw(scratch,incoming)
            if wrapper:h.call('network_connection_dispose',0x886e0,{},[connection],run)
            else:h.call('network_storage_clear',0x94bf0,dict(esi=storage),[],run)
            assert original==native,iteration

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-storage-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_connection.c','include/halo2/network_connection.h','src/network_messages.c','src/network_routing.c','src/message_dispatch.c','tests/network_state_oracle.py','tests/network_send_oracle.py','tests/message_dispatch_oracle.py','src/network_storage.c','include/halo2/network_storage.h','tests/network_storage_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original connection disposal (including close, fresh-writer queue/codec and route removal) and two-queue cleanup, virtual lookup/release boundaries controlled. Full memory, scratch and callback snapshots; inactive/empty/reversed ranges, signed sequence numbers, circular indexing, zero handles, AL failure and untouched output, callback owner/counter/bound mutation. Valid ring capacities and entries; no division-fault equivalence claim. Virtual allocator bodies, full shutdown and game boot remain unfinished.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
