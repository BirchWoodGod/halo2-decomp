#!/usr/bin/env python3
"""Session sends and transitions through actual datagram dispatch and codecs."""
import argparse, ctypes as C, hashlib, json, random, struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT, Memory, EXPECTED
from engine_pools_oracle import BASE, STACK, STOP
from message_dispatch_oracle import NativeCodec, Platform
from network_state_oracle import Operations as Clock, Ticks
from network_send_oracle import Ops as SendOps, Send, Error
from network_storage_queue_oracle import QueueOps, Poll, Allocate, Collect

class Context(C.Structure):
    _fields_=[('clock',C.POINTER(Clock)),('send',C.POINTER(SendOps)),('codec',C.POINTER(Platform)),('resolution',C.c_void_p),('queue',C.c_void_p),('message',C.c_uint32),('local',C.c_uint32),('reliable',C.c_uint32),('packet',C.c_uint32),('workspace',C.POINTER(C.c_uint8))]

def suite(h):
    rng=random.Random(0x62480)
    session=h.table; observer=session+0x8000; writer=session+0xc000; connections=session+0xd000; table=session+0xe000
    endpoint=session+0xe800; socket=session+0xee00; packet=session+0x10000; local=session+0x12000; message=session+0x12100; payload=session+0x12200; oldaddress=session+0x12300
    extra=h.lib.h2_heap_allocate(h.heap,0x15000);assert extra
    storage=extra;wrapper=extra+0x2900;obj=extra+0x2a00;vt=extra+0x2b00;allocations=extra+0x3000;reliable=extra+0x4000
    h.u.mem_map(STACK-0x10000,0x10000)
    original=[]; native=[]; coverage={}; iteration=0;frames={};seeds={}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def u32(read,p):return struct.unpack('<I',read(p,4))[0]
    def event(read,write,events,kind,*args):
        events.append((kind,args,bytes(read(session,0x7900)),bytes(read(storage,0x3800))))
        if events is original:coverage[kind]=coverage.get(kind,0)+1
        if iteration%3==0:
            write(session+0x54,pack(1));write(session+0x72e0,pack(2))
            write(session+0x20,pack(0x87654321));write(0x4cf4b0,pack(3))
        if kind=='poll':return 0
        if kind=='allocate':return allocations+(sum(e[0]=='allocate' for e in events)-1)*32
        if kind=='collect':raise AssertionError('unexpected collection')
        if kind=='ticks':return (1000+len(events)*10)&0xffffffff
        return args[2]
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks'));clock=Clock();clock.ticks=tick
    sendcb=Send(lambda ctx,handle,data,n,flags,addr,length:event(h.read,nw,native,'send',handle,bytes(h.read(data,n)),n,flags,C.string_at(addr,28),length))
    error=Error(lambda ctx:0);send=SendOps(None,sendcb,error)
    codec=Platform();codec_context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(codec_context))
    poll=Poll(lambda ctx,fn,o,v:event(h.read,nw,native,'poll',fn,o,v))
    allocate=Allocate(lambda ctx,fn,o,n,a,b:event(h.read,nw,native,'allocate',fn,o,n,a,b))
    collect=Collect(lambda ctx,fn,o,v:event(h.read,nw,native,'collect',fn,o,v));queue=QueueOps(None,poll,allocate,collect)
    workspace=(C.c_uint8*28)();context=Context(C.pointer(clock),C.pointer(send),C.pointer(codec),None,C.cast(C.pointer(queue),C.c_void_p),message,local,reliable,packet,workspace)
    register=h.lib.h2_messages_register_session;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    enqueue=h.lib.h2_message_writer_enqueue;enqueue.argtypes=[C.POINTER(Memory),C.POINTER(Clock),C.POINTER(SendOps),C.POINTER(Platform)]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];enqueue.restype=C.c_uint8
    modes={'send_peer':(0x62d20,6),'broadcast':(0x62da0,5),'update_leave':(0x62480,1),'begin_leave':(0x61330,1),'begin_disband':(0x61450,1)}
    funcs={}
    for name,(_,argc) in modes.items():
        f=getattr(h.lib,'h2_network_session_'+name);f.argtypes=[C.POINTER(Memory),C.POINTER(Context)]+[C.c_uint32]*argc;f.restype=None;funcs[name]=f
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at in [0x62480,0x61450]:frames['message']=sp-8;return
        if at in [0x6251e,0x61477]:frames['message_bytes']=bytes(u.mem_read(frames['message'],8));return
        if at==0x75e80:
            frames['local']=sp-44;frames['argument']=sp+4;u.mem_write(sp-44,frames.get('local_bytes',seeds[local][:48])[:44]);return
        if at in [0x75f34,0x75fac]:
            frames['local_bytes']=bytes(u.mem_read(frames['local'],44))+bytes(u.mem_read(frames['argument'],4));return
        if at==0x95580:
            frames['reliable']=((sp-4)&~7)-0x10054-12+0x24;u.mem_write(frames['reliable'],seeds[reliable]);return
        if at==0x95835:
            b=bytearray(u.mem_read(frames['reliable'],0x10037));b[:4]=pack(reliable+0x38);frames['reliable_bytes']=bytes(b);return
        if at==0xb5110:u.mem_write(sp-28,bytes(28));return
        if at in [STOP+0x800,STOP+0x900]:
            kind='poll' if at==STOP+0x800 else 'allocate';purge=4 if kind=='poll' else 12
            args=struct.unpack('<'+'I'*(purge//4),u.mem_read(sp+4,purge))
            value=event(u.mem_read,u.mem_write,original,kind,at,u.reg_read(X.UC_X86_REG_ECX),*args)
        elif at==0x3314b0:value=event(u.mem_read,u.mem_write,original,'ticks');purge=0
        else:
            handle,data,n,flags,addr,length=struct.unpack('<6I',u.mem_read(sp+4,24))
            value=event(u.mem_read,u.mem_write,original,'send',handle,bytes(u.mem_read(data,n)),n,flags,bytes(u.mem_read(addr,28)),length);purge=24
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x62480,0x61450,0x6251e,0x61477,0x75e80,0x75f34,0x75fac,0x95580,0x95835,0xb5110,0x3314b0,0x3cd254,STOP+0x800,STOP+0x900]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    for mode,(address,_) in modes.items():
        for iteration in range(256):
            original.clear();native.clear();frames.clear();h.write(session,rng.randbytes(0x7900));h.write(observer,bytes(0x3000));h.write(connections,bytes(0x400))
            h.write(extra,bytes(0x15000));h.write(storage,pack(vt));h.write(storage+12,pack(table));h.write(storage+20,pack(32));h.write(vt+4,pack(STOP+0x800));h.write(vt+0x14,pack(STOP+0x900));h.write(wrapper,pack(obj));h.write(obj,pack(vt));h.write(0x4d87f8,pack(wrapper));h.write(0x4d87dc,pack(storage))
            h.write(session+8,pack(observer));h.write(session+0x10,pack(0));h.write(session+0x40,pack(iteration%3));h.write(session+0x54,pack([0,1,2,3,0xffffffff,0x80000000][iteration%6]))
            h.write(0x4d87d4,pack(connections));h.write(0x510548,pack(iteration%2));h.write(0x51054c,pack(1000));h.write(0x4cf4b0,pack([0,10,100,0xffffffff,0x80000000][iteration%5]));h.write(0x4d8b18,b'\1\1')
            h.write(session+0x7424,pack([0xffffffff,0,999,1000,1001,0x80000000][iteration//5%6]))
            for i in range(3):
                peer=session+0x72dc+i*20;entry=observer+0xa8+i*0x528
                h.write(peer+1,bytes([0 if (iteration+i)%7==0 else 255]));h.write(peer+4,pack(i));h.write(entry,pack(7 if (iteration+i)%2 else 6));h.write(entry+12,pack(0xffffffff if (iteration+i)%11==0 else i));h.write(connections+i*0xf8+0x54,pack(2 if iteration%4==0 else 3))
                h.write(entry+0x5c,pack(0x7f000001+i)+bytes(12)+struct.pack('<HH',1000,4))
            h.write(writer,bytes(0x700));h.write(writer+12,pack(table));h.write(writer+8,pack(endpoint));h.write(observer+8,pack(writer))
            h.write(endpoint,bytes(0x588));h.write(endpoint+0x18,pack(socket));h.write(socket,pack(17))
            for off in [0x228,0x3d8]:h.write(endpoint+off+0x10,pack(100));h.write(endpoint+off+0x20,pack(100))
            h.write(payload,rng.randbytes(8));h.write(oldaddress,pack(0xdeadbeef)+bytes(12)+struct.pack('<HH',1001,4))
            seeds={local:rng.randbytes(80),message:rng.randbytes(8),packet:rng.randbytes(0x1828),reliable:bytes(0x10037)}
            for p,b in seeds.items():h.write(p,b)
            C.memset(workspace,0,28)
            assert enqueue(h.memory,C.byref(clock),C.byref(send),C.byref(codec),writer,oldaddress,11,8,payload,packet,workspace)
            h.write(writer,h.read(writer,0x700));native.clear()
            sendmode=[0,1,2,3,0xffffffff][iteration//3%5]
            regs={'send_peer':dict(esi=session,eax=iteration%3,ebx=sendmode),'broadcast':dict(ecx=session,eax=sendmode),'update_leave':dict(esi=session),'begin_leave':dict(eax=session),'begin_disband':dict(esi=session)}
            args=[11,8,payload] if mode in ['send_peer','broadcast'] else []
            nativeargs={'send_peer':[session,iteration%3,sendmode,11,8,payload],'broadcast':[session,sendmode,11,8,payload]}.get(mode,[session])
            def run():
                funcs[mode](h.memory,C.byref(context),*nativeargs)
                assert h.read(message,8)==frames.get('message_bytes',seeds[message]),(mode,iteration,'message scratch')
                assert h.read(local,48)==frames.get('local_bytes',seeds[local][:48]),(mode,iteration,'dispatcher scratch')
                assert h.read(reliable,0x10037)==frames.get('reliable_bytes',seeds[reliable]),(mode,iteration,'reliable scratch')
                for p,b in seeds.items():nw(p,b)
            try:h.call(mode,address,regs[mode],args,run,None)
            except Exception:
                print('mode',mode,'iteration',iteration,'eip',hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
            assert original==native,(mode,iteration,'events')
    assert all(coverage.get(k) for k in ['send','ticks','poll','allocate']),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-send-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_send.c','src/network_storage_queue.c','src/network_resolution.c','src/message_dispatch.c','src/network_messages.c','src/network_packet.c','src/network_send.c','src/network_endpoint.c','src/network_session_send.c','include/halo2/network_session_send.h','tests/network_session_send_oracle.py','tests/network_storage_queue_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py','tests/network_send_oracle.py','tests/message_dispatch_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Session send/broadcast and leave/disband transitions with actual observer dispatch, cached datagrams, codecs, queue and flush. SDK ticks/send controlled with session mutations. Reliable state 2/3 connections execute actual queue/header/codec/CRC/fragmentation; poll/allocation callbacks controlled. Message, dispatcher and normalized reliable stack scratch compared before restoration; packet scratch covered separately by dispatcher oracle. No live Linux networking or playable startup.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
