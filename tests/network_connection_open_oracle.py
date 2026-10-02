#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops
from message_dispatch_oracle import NativeCodec,Platform
from network_connection_oracle import Callbacks,Closed
from network_storage_oracle import Operations as StorageOps,Lookup,Release

def suite(h):
    rng=random.Random(0x88220);writer=h.table;table=writer+0x1000;endpoint=writer+0x2000;conn=writer+0x3000;config=conn+0x200;alternate=config+0x20;record=config+0x40;message=config+0x60;local=message+16;packet=writer+0x4000;stub=0x3000800;address=writer+0x7000;stream=writer+0x8000;storage=writer+0xa000;storage_local=local+16;old=conn+0xf8;owner=storage+0x3000;object_address=owner+0x20;vtable=owner+0x40;lookup_at=0x3000900;release_at=0x3000a00
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    original=[];native=[];frames={};coverage={'ticks':0,'close':0,'enqueue':0,'requests':0,'route':0,'stream':0,'storage':0,'dispose':0,'lookup':0,'release':0};iteration=0
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def tick_event(read,write,events):
        events.append(('tick',bytes(read(conn,0xf8)),bytes(read(writer,0x700)),bytes(read(config,0x40))))
        if events is original:coverage['ticks']+=1
        if iteration%3==0:
            write(conn+12,pack(alternate));write(conn+0x88,pack(0x80000000));write(conn+0x8c,pack(3))
            write(alternate,pack(0xfffffff0+len(events)))
        if iteration%7==0:write(0x510548,b'\1');write(0x51054c,pack(17))
        return [0,1,100,0xfffffff0,0x80000000][iteration//2%5]+len(events)&0xffffffff
    def closed(read,write,events,function,argument):
        events.append(('closed',function,argument,bytes(read(conn,0xf8)),bytes(read(writer,0x700))))
        if iteration%3==0:write(conn+0x70,bytes(range(20)));write(argument+0x44,pack(9))
        if iteration%11==0:write(conn+0x84,b'\0');write(endpoint+0x20,pack(16))
    def storage_event(read,write,events,kind,function,obj,handle,arg,scratch):
        events.append((kind,function,obj,handle,arg-scratch if kind=='lookup' else arg,bytes(read(storage,0x2850)),bytes(read(scratch,8)),bytes(read(owner,8))))
        if events is original:coverage[kind]+=1
        if kind=='lookup':
            if iteration%3:write(arg,pack(0x87654321))
            if iteration%13==0:write(conn+0x14,pack(0xffffffff))
            return 0 if iteration%5==0 else 255
        if iteration%7==0:write(owner+4,pack(0))
        return 0
    lookup=Lookup(lambda ctx,f,o,v,out:storage_event(h.read,nw,native,'lookup',f,o,v,out,storage_local))
    release=Release(lambda ctx,f,o,v,arg:storage_event(h.read,nw,native,'release',f,o,v,arg,storage_local));storage_ops=StorageOps(None,lookup,release)
    tick=Ticks(lambda ctx:tick_event(h.read,nw,native));clock=Operations(None,tick,Provider())
    cb=Closed(lambda ctx,f,a:closed(h.read,nw,native,f,a));callbacks=Callbacks(None,cb);send=Ops();codec=Platform();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x94ddd:frames['storage_result']=bytes(u.mem_read(frames['storage'],8));return
        if at in [lookup_at,release_at]:
            handle,arg=struct.unpack('<II',u.mem_read(esp+4,8));kind='lookup' if at==lookup_at else 'release'
            result=storage_event(u.mem_read,u.mem_write,original,kind,at,u.reg_read(X.UC_X86_REG_ECX),handle,arg,frames['storage'])
            u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+12);return
        if at in [0x92d10,0x95cf0,0x94bf0,0x886e0]:
            if at==0x94bf0:frames['storage']=esp-8;u.mem_write(esp-8,frames.get('storage_result',storage_incoming))
            coverage[{0x92d10:'route',0x95cf0:'stream',0x94bf0:'storage',0x886e0:'dispose'}[at]]+=1
            return
        if at==0x890b0:frames['message']=esp-8;u.mem_write(esp-8,incoming);return
        if at==0x886d6:frames['close_result']=bytes(u.mem_read(frames['close'],12));return
        if at in [0x890e8,0x89154,0x89172]:frames['result']=bytes(u.mem_read(frames['message'],8));return
        if at==0x88650:coverage['close']+=1;frames['close']=esp-12;u.mem_write(esp-12,frames.get('close_result',close_incoming));return
        if at==0x7b140:
            coverage['enqueue']+=1
            if struct.unpack('<I',u.mem_read(esp+12,4))[0]==4:coverage['requests']+=1
            return
        if at==0x3314b0:u.reg_write(X.UC_X86_REG_EAX,tick_event(u.mem_read,u.mem_write,original));purge=0
        else:
            argument=struct.unpack('<I',u.mem_read(esp+4,4))[0];closed(u.mem_read,u.mem_write,original,at,argument);purge=4
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for at in [lookup_at,release_at,0x94ddd,0x92d10,0x95cf0,0x94bf0,0x886e0,0x886d6,0x890b0,0x890e8,0x89154,0x89172,0x88650,0x7b140,0x3314b0,stub]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_connection_open;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks),C.c_void_p]+[C.c_uint32]*2+[C.c_uint8]+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];fn.restype=None
    for iteration in range(1024):
        original.clear();native.clear();frames.clear();incoming=rng.randbytes(8);close_incoming=rng.randbytes(12);h.write(message,incoming);h.write(local,close_incoming);storage_incoming=rng.randbytes(8);h.write(storage_local,storage_incoming)
        h.write(writer,bytes(0x700));h.write(writer+8,pack(endpoint)+pack(table));h.write(endpoint,bytes(0x224));h.write(endpoint+0x20,pack(1));h.write(endpoint+0x24,pack(0))
        h.write(conn,rng.randbytes(0xf8));h.write(conn,pack(endpoint)+pack(writer));h.write(conn+12,pack(config));h.write(conn+0x3c,pack(record));h.write(record+4,pack(conn)+pack(stub));h.write(conn+0x44,pack(0));h.write(conn+0x54,pack([2,3,5][iteration//10%3]));h.write(conn+0x82,struct.pack('<H',4))
        h.write(0x4d87d4,pack(conn));h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack([0,1,100,0xfffffff0,0x80000000][iteration//2%5]))
        h.write(conn+0x88,pack([0,1,0xfffffff0,0x80000000][iteration//30%4]));h.write(conn+0x8c,pack([0,1,101,0xffffffff][iteration//120%4]));h.write(conn+0x90,pack([0,1,4,0xffffffff][iteration//240%4]))
        for cfg in [config,alternate]:h.write(cfg,pack(rng.getrandbits(32))+pack([0,1,5,0x7fffffff][iteration//6%4])+pack([0,100,0x7fffffff,0xffffffff][iteration//24%4]))
        h.write(conn+0x10,pack(0 if iteration%3 else 0xffffffff));h.write(conn+0x14,pack(0 if iteration%4 else 0xffffffff))
        h.write(stream,rng.randbytes(0x97c));h.write(storage,rng.randbytes(0x2850));h.write(storage+4,bytes([iteration%2]))
        for off in [0x18,0x1c,0x1834,0x1838]:h.write(storage+off,pack(0))
        h.write(0x4d87d8,pack(stream));h.write(0x4d87dc,pack(storage));h.write(0x4cf6e8,pack(iteration));h.write(0x4cf70c,rng.randbytes(16));h.write(0x4e6398,rng.randbytes(8))
        addr=pack([0x7f000001,0x00123456,0][iteration//3%3])+rng.randbytes(12)+struct.pack('<HH',1000,[4,16,0,0xffff][iteration//9%4]);h.write(address,addr)
        h.write(endpoint+4,pack([0,1,0xfffffffe,0xffffffff][iteration//36%4]));h.write(endpoint+0x20,pack([0,1,16][iteration//144%3]))
        for k in range(16):h.write(endpoint+0x24+k*32,pack(1));h.write(endpoint+0x30+k*32,addr)
        h.write(old,rng.randbytes(0xf8));h.write(old,pack(endpoint)+pack(writer));h.write(old+0x10,pack(0xffffffff)*2);h.write(old+0x3c,pack(record+16));h.write(record+20,pack(old)+pack(stub));h.write(old+0x44,pack(1));h.write(old+0x48,pack(0xc0));h.write(old+0x54,pack(3));h.write(old+0x4c,pack(iteration%2));h.write(old+0x70,addr)
        h.write(0x4d87f8,pack(owner));h.write(owner,pack(object_address)+pack(8));h.write(object_address,pack(vtable));h.write(vtable,pack(release_at)+pack(lookup_at))
        for offset,stride in [(0,12),(0x181c,8)]:
            n=iteration//4%3
            h.write(storage+offset+0x14,pack(8)+pack(n)+pack(0));h.write(storage+offset+0x24,pack(0)+pack(1))
            for k in range(n):h.write(storage+offset+0x2c+k*stride+1,b'\3');h.write(storage+offset+0x30+k*stride,pack(17+k))
        if iteration%6==0:h.write(old+0x14,pack(0))
        active=[0,1,2,255][iteration//2%4]
        def run():
            fn(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),C.byref(storage_ops),conn,address,active,message,local,storage_local,packet,(C.c_uint8*28)())
            assert h.read(message,8)==frames.get('result',incoming),iteration
            if 'close' in frames:assert h.read(local,12)==frames['close_result'],iteration
            assert h.read(storage_local,8)==frames.get('storage_result',storage_incoming)
            nw(storage_local,storage_incoming)
            nw(message,incoming);nw(local,close_incoming)
        h.call('connection_open',0x88220,dict(eax=address),[conn,active],run)
        assert original==native,iteration
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-open-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_connection_open.c','include/halo2/network_connection_open.h','src/network_connection_setup.c','src/network_route_insert.c','src/network_storage.c','tests/network_storage_oracle.py','tests/network_connection_open_oracle.py','src/network_handshake.c','include/halo2/network_handshake.h','src/network_connection.c','src/network_messages.c','src/message_dispatch.c','src/network_routing.c','tests/network_handshake_oracle.py','tests/network_connection_oracle.py','tests/message_dispatch_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),boundary_coverage=coverage,comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original connection open instructions with actual route insertion, disposal, timer/stream reset and allocated storage clear with queued handles. Original handshake instructions and actual close, queue, message codecs, route removal. Full guest memory and scratch; clock/config/override mutation, signed wrap, timeout and retry limits. Fresh writer avoids flush/send; SDK clock and close callback controlled. Storage virtual lookup/release boundaries controlled; no gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
