#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_observer_tick_oracle import Context
from network_connection_oracle import Callbacks,Closed
from network_send_oracle import Ops
from message_dispatch_oracle import NativeCodec,Platform

def suite(h):
    rng=random.Random(0x773a0);observer=h.table;writer=observer+0x6000;table=observer+0x7000
    endpoint=observer+0x8000;conn=observer+0x9000;record=conn+0x200
    config=observer+0xa000;alternate=config+0x200;local=config+0x400;packet=observer+0xb000;stub=0x3000800
    original=[];native=[];frames={};coverage={'close':0,'enqueue':0,'ticks':0};iteration=0;entry=0
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,*args):
        events.append((kind,args,bytes(read(observer,0x1800)),bytes(read(conn,0xf8)),bytes(read(writer,0x700))))
        if kind=='tick':
            n=sum(e[0]=='tick' for e in events)
            if events is original:coverage['ticks']+=1
            if iteration%7==0:write(conn+0x54,pack(1))
            if iteration%11==0:write(observer+16,pack(alternate))
            if iteration%13==0:write(0x510548,b'\1');write(0x51054c,pack(100))
            return ([0,1,100,0xfffffff0,0x80000000][iteration//2%5]+n)&0xffffffff
        write(conn+0x54,pack(99));return 0
    tick=Ticks(lambda ctx:event(h.read,nw,native,'tick'));clock=Operations(None,tick,Provider())
    closed=Closed(lambda ctx,f,a:event(h.read,nw,native,'closed',f,a));callbacks=Callbacks(None,closed)
    send=Ops();codec=Platform();codec_context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(codec_context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    context=Context();ptr=lambda x:C.cast(C.pointer(x),C.c_void_p).value
    context.clock=ptr(clock);context.send=ptr(send);context.codec=ptr(codec);context.connections=ptr(callbacks)
    workspace=(C.c_uint8*28)();context.workspace28=workspace;context.detach16=local;context.packet=packet
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x88650:
            frames['local']=sp-12;u.mem_write(sp-12,incoming);coverage['close']+=1;return
        if at==0x7b140:coverage['enqueue']+=1;return
        if at==0x3314b0:
            value=event(u.mem_read,u.mem_write,original,'tick');u.reg_write(X.UC_X86_REG_EAX,value);purge=0
        else:
            arg=struct.unpack('<I',u.mem_read(sp+4,4))[0];event(u.mem_read,u.mem_write,original,'closed',at,arg);purge=4
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x88650,0x7b140,0x3314b0,stub]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_check_timeout;fn.argtypes=[C.POINTER(Memory),C.POINTER(Context),C.c_uint32,C.c_uint32];fn.restype=None
    values=[0,1,99,100,101,0x7fffffff,0x80000000,0xffffffff]
    for iteration in range(2048):
        original.clear();native.clear();frames.clear();incoming=rng.randbytes(12)
        h.write(observer,rng.randbytes(0x1800));h.write(conn,rng.randbytes(0xf8));h.write(local,incoming)
        index=iteration%4;entry=observer+0xa8+index*0x528
        h.write(entry,pack(0 if iteration%17==0 else 2));h.write(entry+12,pack(0xffffffff if iteration%19==0 else 0))
        h.write(entry+0x94,pack(values[iteration//4%8]));h.write(observer+16,pack(config))
        h.write(0x4d87d4,pack(conn));h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack(values[iteration//8%8]))
        h.write(conn+0x54,pack([5,5,5,2,0xffffffff][iteration//16%5]));h.write(conn+0x98,pack(values[iteration//32%8]));h.write(conn+0xc8,pack(values[iteration//64%8]))
        for bank,offset in [(config,0),(alternate,3)]:
            for k,off in enumerate([0x74,0x80,0x84]):h.write(bank+off,pack(values[(iteration//(k+1)+offset)%8]))
        h.write(writer,bytes(0x700));h.write(writer+8,pack(endpoint)+pack(table));h.write(endpoint,bytes(0x224));h.write(endpoint+0x20,pack(1));h.write(endpoint+0x24,pack(0))
        h.write(conn,pack(endpoint)+pack(writer));h.write(conn+0x3c,pack(record));h.write(record+4,pack(conn)+pack(stub));h.write(conn+0x44,pack(0));h.write(conn+0x82,struct.pack('<H',4))
        def run():
            fn(h.memory,C.byref(context),observer,index)
            if 'local' in frames:assert h.read(local,12)==bytes(h.u.mem_read(frames['local'],12)),iteration
            nw(local,incoming)
        h.call('observer_timeout',0x773a0,dict(eax=index),[observer],run)
        assert original==native,iteration
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-timeout-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_timeout.c','include/halo2/network_observer_timeout.h','tests/network_observer_timeout_oracle.py','src/network_observer_retry.c','src/network_connection.c','src/network_messages.c','tests/network_observer_tick_oracle.py']
    report=dict(passed=True,total_comparisons=sum(h.counts.values()),comparisons=h.counts,coverage=coverage,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original773a0 with actual elapsed, connection-close, enqueue/codec and route-removal callees. Signed wraparound and mutable clock/state/config/override; full memory, close scratch and callback snapshots. Fresh writer queues close packets but does not flush to network.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
