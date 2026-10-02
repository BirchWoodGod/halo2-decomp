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

def suite(h):
    rng=random.Random(0x890b0);writer=h.table;table=writer+0x1000;endpoint=writer+0x2000;conn=writer+0x3000;config=conn+0x200;alternate=config+0x20;record=config+0x40;message=config+0x60;local=message+16;packet=writer+0x4000;stub=0x3000800
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    original=[];native=[];frames={};coverage={'ticks':0,'close':0,'enqueue':0,'requests':0};iteration=0
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
        if iteration%3==0:write(conn+0x70,bytes(range(20)));write(conn+0x44,pack(9))
    tick=Ticks(lambda ctx:tick_event(h.read,nw,native));clock=Operations(None,tick,Provider())
    cb=Closed(lambda ctx,f,a:closed(h.read,nw,native,f,a));callbacks=Callbacks(None,cb);send=Ops();codec=Platform();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x890b0:frames['message']=esp-8;u.mem_write(esp-8,incoming);return
        if at in [0x890e8,0x89154,0x89172]:frames['result']=bytes(u.mem_read(frames['message'],8));return
        if at==0x88650:coverage['close']+=1;frames['close']=esp-12;u.mem_write(esp-12,close_incoming);return
        if at==0x7b140:
            coverage['enqueue']+=1
            if struct.unpack('<I',u.mem_read(esp+12,4))[0]==4:coverage['requests']+=1
            return
        if at==0x3314b0:u.reg_write(X.UC_X86_REG_EAX,tick_event(u.mem_read,u.mem_write,original));purge=0
        else:
            argument=struct.unpack('<I',u.mem_read(esp+4,4))[0];closed(u.mem_read,u.mem_write,original,at,argument);purge=4
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for at in [0x890b0,0x890e8,0x89154,0x89172,0x88650,0x7b140,0x3314b0,stub]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_connection_update_handshake;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks)]+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];fn.restype=None
    for iteration in range(1024):
        original.clear();native.clear();frames.clear();incoming=rng.randbytes(8);close_incoming=rng.randbytes(12);h.write(message,incoming);h.write(local,close_incoming)
        h.write(writer,bytes(0x700));h.write(writer+8,pack(endpoint)+pack(table));h.write(endpoint,bytes(0x224));h.write(endpoint+0x20,pack(1));h.write(endpoint+0x24,pack(0))
        h.write(conn,rng.randbytes(0xf8));h.write(conn,pack(endpoint)+pack(writer));h.write(conn+12,pack(config));h.write(conn+0x3c,pack(record));h.write(record+4,pack(conn)+pack(stub));h.write(conn+0x44,pack(0));h.write(conn+0x54,pack([2,3,5][iteration//10%3]));h.write(conn+0x82,struct.pack('<H',4))
        h.write(0x4d87d4,pack(conn));h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack([0,1,100,0xfffffff0,0x80000000][iteration//2%5]))
        h.write(conn+0x88,pack([0,1,0xfffffff0,0x80000000][iteration//30%4]));h.write(conn+0x8c,pack([0,1,101,0xffffffff][iteration//120%4]));h.write(conn+0x90,pack([0,1,4,0xffffffff][iteration//240%4]))
        for cfg in [config,alternate]:h.write(cfg,pack(rng.getrandbits(32))+pack([0,1,5,0x7fffffff][iteration//6%4])+pack([0,100,0x7fffffff,0xffffffff][iteration//24%4]))
        def run():
            fn(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),conn,message,local,packet,(C.c_uint8*28)())
            assert h.read(message,8)==frames['result'],iteration
            if 'close' in frames:assert h.read(local,12)==bytes(h.u.mem_read(frames['close'],12)),iteration
            nw(message,incoming);nw(local,close_incoming)
        h.call('connection_update_handshake',0x890b0,dict(eax=conn),[],run)
        assert original==native,iteration
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-handshake-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_handshake.c','include/halo2/network_handshake.h','src/network_connection.c','src/network_messages.c','src/message_dispatch.c','src/network_routing.c','tests/network_handshake_oracle.py','tests/network_connection_oracle.py','tests/message_dispatch_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),boundary_coverage=coverage,comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original handshake instructions and actual close, queue, message codecs, route removal. Full guest memory and scratch; clock/config/override mutation, signed wrap, timeout and retry limits. Fresh writer avoids flush/send; SDK clock and close callback controlled. Not full connection open or gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
