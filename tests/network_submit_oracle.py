#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_send_oracle import Ops,Send,Error
from network_state_oracle import Operations as ClockOps,Ticks,Provider
from message_dispatch_oracle import NativeCodec
Encode=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class Codecs(C.Structure):
    _fields_=[("context",C.c_void_p),("encode",Encode)]

def suite(h):
    rng=random.Random(0x932f0);packet=h.table;endpoint=packet+0x1000;socket=packet+0x2000;connections=packet+0x2200;scratch=packet+0x4000
    original=[];native=[];result=0;err=0;mutate=False;incoming=bytes(28);frames={};flush_mode=False;codec_mode=False;stub=0x3000800
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,args):
        events.append((kind,args,bytes(read(packet,0x824)),bytes(read(endpoint,0x588))))
        if kind=='ticks':
            number=sum(e[0]=='ticks' for e in events)
            if mutate:
                if number==1:write(packet+0x1c,struct.pack('<I',17));write(packet+0x620,struct.pack('<I',0xffffff00))
                else:write(packet,struct.pack('<I',3))
            return 1000+number*100
        if flush_mode and kind=='send':write(packet+0x14,b'\x55')
        return result if kind=='send' else err
    send_cb=Send(lambda ctx,handle,data,length,flags,addr,n:event(h.read,nw,native,'send',(handle,bytes(h.read(data,length)),length,flags,C.string_at(addr,28),n)))
    error_cb=Error(lambda ctx:event(h.read,nw,native,'error',()))
    tick_cb=Ticks(lambda ctx:event(h.read,nw,native,'ticks',()))
    ops=Ops(None,send_cb,error_cb);clock=ClockOps(None,tick_cb,Provider())
    def hook(u,at,size,ctx):
        nonlocal incoming
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x93182:frames['packet_bytes']=bytes(u.mem_read(frames['packet'],0x824));return
        if at==0x933d6:
            n=struct.unpack('<I',u.mem_read(frames['packed'],4))[0];frames['packed_bytes']=bytes(u.mem_read(frames['packed'],4+n));return
        if codec_mode and at in [0xad230,0xac580,0xaca40,stub]:
            stream,size,payload=struct.unpack('<III',u.mem_read(esp+4,12));event(u.mem_read,u.mem_write,original,'codec',(at,stream,size,bytes(u.mem_read(payload,size))))
            if at==stub:
                position=struct.unpack('<I',u.mem_read(stream+16,4))[0];u.mem_write(stream+16,struct.pack('<I',(position+0x3000)&0xffffffff));u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+16)
            return
        if at in [0xad230,0xac580,0xaca40,stub]:return
        if at==0x93100:frames['packet']=((esp-4)&~7)-0x828;return
        if at==0x932f0:frames['packed']=esp-0x1004;return
        if at==0xb5110:
            incoming=bytes(u.mem_read(esp-28,28));return # Observe only; execute original callee.
        if at==0x3cd254:
            handle,data,length,flags,addr,n=struct.unpack('<6I',u.mem_read(esp+4,24))
            value=event(u.mem_read,u.mem_write,original,'send',(handle,bytes(u.mem_read(data,length)),length,flags,bytes(u.mem_read(addr,28)),n));purge=24
        else:value=event(u.mem_read,u.mem_write,original,'ticks' if at==0x3314b0 else 'error',());purge=0
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for at in [0x93182,0x933d6,0xad230,0xac580,0xaca40,stub,0x93100,0x932f0,0xb5110,0x3cd254,0x3cd718,0x3314b0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_packet_submit;fn.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.POINTER(Ops)]+[C.c_uint32]*3+[C.POINTER(C.c_uint8)];fn.restype=None
    for i in range(192):
        h.write(packet,rng.randbytes(0x3000));h.write(scratch,rng.randbytes(0x1004));before=h.read(scratch,0x1004)
        kind=i%4;primary=[0,1,12,0x518,0x519,0x600][i//4%6];secondary=[0,2,31][i//7%3]
        h.write(packet,struct.pack('<I',kind));h.write(packet+0x1c,struct.pack('<I',primary));h.write(packet+0x620,struct.pack('<I',secondary))
        width=[4,16,0][i//5%3];h.write(packet+0x1a,struct.pack('<H',width));h.write(packet+8,struct.pack('<I',0x7f000001 if i%9==0 else 0x0a010203))
        for j in range(4):h.write(endpoint+12+j*4,struct.pack('<I',0 if i%13==0 else socket))
        h.write(socket,struct.pack('<I',17));h.write(endpoint+0x20,struct.pack('<I',1));h.write(endpoint+0x24,struct.pack('<I',0));h.write(endpoint+0x30,h.read(packet+8,20));h.write(0x4d87d4,struct.pack('<I',connections));h.write(connections+0x54,struct.pack('<I',8));h.write(connections+0x48,b'\xc0')
        for off in [0x228,0x3d8]:
            if i%4==0:h.write(endpoint+off,struct.pack('<4I',0xffffffff,0xffffffff,0xfffffffe,0xffffffff))
            h.write(endpoint+off+0x10,struct.pack('<I',100));h.write(endpoint+off+0x20,struct.pack('<I',100));h.write(endpoint+off+0x28,struct.pack('<I',i%20))
        h.write(0x510548,struct.pack('<II',i%2,1500));h.write(0x4d8b18,bytes([0 if i%17==0 else 1,1]));result=[0,12,0xffff,0xffffffff][i//3%4];err=[0,0x2733,0x2751][i//11%3];mutate=i%3==0
        original.clear();native.clear();incoming=bytes(28)
        def run():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            fn(h.memory,C.byref(clock),C.byref(ops),packet,endpoint,scratch,workspace)
            # Native guest scratch models original transient stack storage.
            n=h.u32(scratch);assert h.read(scratch,4+n)==bytes(h.u.mem_read(0x2008000-0x1004,4+n))
            nw(scratch,before)
        h.call('packet_submit',0x932f0,dict(ecx=packet),[endpoint],run)
        assert original==native,(i,original,native)

    outer=h.lib.h2_network_packet_send_datagram
    outer.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.POINTER(Ops)]+[C.c_uint32]*5+[C.POINTER(C.c_uint8)];outer.restype=None
    stream=packet+0x900;size_out=stream+8
    for i in range(96):
        h.write(packet,rng.randbytes(0x3000));h.write(scratch,rng.randbytes(0x1828));before=h.read(scratch,0x1828)
        size=[0,1,12,0x518,0x519,0x600,0x601,0xffffffff][i%8]
        h.write(stream,struct.pack('<II',packet+0x20,size));h.write(packet+8,struct.pack('<I',0x7f000001 if i%3==0 else 0x0a010203));h.write(packet+0x1a,struct.pack('<H',4 if i%2 else 16))
        h.write(endpoint+0x18,struct.pack('<I',socket));h.write(socket,struct.pack('<I',17));h.write(endpoint+0x20,struct.pack('<I',0))
        for off in [0x228,0x3d8]:
            if i%4==0:h.write(endpoint+off,struct.pack('<4I',0xffffffff,0xffffffff,0xfffffffe,0xffffffff))
            h.write(endpoint+off+0x10,struct.pack('<I',100));h.write(endpoint+off+0x20,struct.pack('<I',100));h.write(endpoint+off+0x28,struct.pack('<I',i%20))
        h.write(0x510548,struct.pack('<II',i%2,1500));h.write(0x4d8b18,b'\1\1');result=0xffff if i%2 else 1;err=0x2751;mutate=bool(i%3);original.clear();native.clear();incoming=bytes(28);out=size_out if i%4 else 0
        def run_outer():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            outer(h.memory,C.byref(clock),C.byref(ops),stream,packet+8,endpoint,out,scratch,workspace)
            assert h.read(scratch,0x824)==bytes(h.u.mem_read(0x2008000-0x830,0x824))
            if size<=0x600:
                n=h.u32(scratch+0x824);assert h.read(scratch+0x824,4+n)==bytes(h.u.mem_read(0x2008000-0x1844,4+n))
            nw(scratch,before)
        h.call('send_datagram',0x93100,dict(ebx=stream,edx=packet+8),[endpoint,out],run_outer)
        assert original==native

    flush=h.lib.h2_message_writer_flush
    flush.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.POINTER(Ops),C.c_uint32,C.c_uint32,C.POINTER(C.c_uint8)];flush.restype=None
    flush_mode=True
    for i in range(160):
        h.write(packet,rng.randbytes(0x3000));h.write(scratch,rng.randbytes(0x1828));before=h.read(scratch,0x1828);frames.clear()
        active=[0,1,255][i%3];position=[0,7,8,31,63,0x28bf,0x3000,0x7fffffff,0xffffffff,0xfffffffe][i//3%10];alignment=[1,4,16,0xffffffff,0xfffffff8][i//7%5]
        h.write(packet+8,struct.pack('<I',endpoint));h.write(packet+0x14,bytes([active]));h.write(packet+0x618,struct.pack('<I',0x7f000001 if i%5==0 else 0x0a010203));h.write(packet+0x62a,struct.pack('<H',4 if i%2 else 16));h.write(packet+0x62c,struct.pack('<IIIII',packet+0x15,0x518,alignment,1,position))
        h.write(endpoint+0x18,struct.pack('<I',socket));h.write(socket,struct.pack('<I',17));h.write(endpoint+0x20,struct.pack('<I',0))
        for off in [0x228,0x3d8]:
            h.write(endpoint+off+0x10,struct.pack('<I',100));h.write(endpoint+off+0x20,struct.pack('<I',100));h.write(endpoint+off+0x28,struct.pack('<I',i%20))
        h.write(0x510548,struct.pack('<II',i%2,1500));h.write(0x4d8b18,b'\1\1');result=0xffff if i%2 else 1;err=0x2751;mutate=bool(i%3);original.clear();native.clear();incoming=bytes(28)
        def run_flush():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            flush(h.memory,C.byref(clock),C.byref(ops),packet,scratch,workspace)
            if 'packet' in frames:assert h.read(scratch,0x824)==bytes(h.u.mem_read(frames['packet'],0x824))
            if 'packed' in frames:
                n=h.u32(scratch+0x824);assert h.read(scratch+0x824,4+n)==bytes(h.u.mem_read(frames['packed'],4+n))
            nw(scratch,before)
        h.call('writer_flush',0x7b330,dict(edi=packet),[],run_flush)
        assert original==native
        assert h.read(packet+0x14,1)==b'\0'

    flush_address=h.lib.h2_message_writer_flush_address
    flush_address.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.POINTER(Ops)]+[C.c_uint32]*3+[C.POINTER(C.c_uint8)];flush_address.restype=None
    match_address=packet+0x700
    for i in range(160):
        h.write(packet,rng.randbytes(0x3000));h.write(scratch,rng.randbytes(0x1828));before=h.read(scratch,0x1828);frames.clear()
        active=[0,1,255][i%3];position=[0,7,8,31,63,0x28bf,0x3000,0x7fffffff,0xffffffff,0xfffffffe][i//3%10];alignment=[1,4,16,0xffffffff,0xfffffff8][i//7%5]
        h.write(packet+8,struct.pack('<I',endpoint));h.write(packet+0x14,bytes([active]));h.write(packet+0x618,struct.pack('<I',0x7f000001 if i%5==0 else 0x0a010203));h.write(packet+0x62a,struct.pack('<H',4 if i%2 else 16));h.write(packet+0x62c,struct.pack('<IIIII',packet+0x15,0x518,alignment,1,position))
        h.write(endpoint+0x18,struct.pack('<I',socket));h.write(socket,struct.pack('<I',17));h.write(endpoint+0x20,struct.pack('<I',0))
        for off in [0x228,0x3d8]:
            h.write(endpoint+off+0x10,struct.pack('<I',100));h.write(endpoint+off+0x20,struct.pack('<I',100));h.write(endpoint+off+0x28,struct.pack('<I',i%20))
        h.write(0x510548,struct.pack('<II',i%2,1500));h.write(0x4d8b18,b'\1\1');result=0xffff if i%2 else 1;err=0x2751;mutate=bool(i%3);original.clear();native.clear();incoming=bytes(28)
        width=[0,4,16,0xffff,0x8000][i%5]
        h.write(packet+0x62a,struct.pack('<H',width));h.write(match_address,h.read(packet+0x618,20))
        if i%7==0:h.write(match_address+18,struct.pack('<H',8))
        if i%3==0:h.write(match_address,struct.pack('<I',h.u32(match_address)^1))
        def run_flush_address():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            flush_address(h.memory,C.byref(clock),C.byref(ops),packet,match_address,scratch,workspace)
            if 'packet' in frames:assert h.read(scratch,0x824)==bytes(h.u.mem_read(frames['packet'],0x824))
            if 'packed' in frames:
                n=h.u32(scratch+0x824);assert h.read(scratch+0x824,4+n)==bytes(h.u.mem_read(frames['packed'],4+n))
            nw(scratch,before)
        h.call('writer_flush_address',0x7b390,dict(ebx=packet,eax=match_address),[],run_flush_address)
        assert original==native

    codec_mode=True;flush_mode=False
    native_codec=NativeCodec(h.memory,C.pointer(clock),0);native_platform=Codecs()
    init_codec=h.lib.h2_message_native_codec_init;init_codec.argtypes=[C.POINTER(Codecs),C.POINTER(NativeCodec)];init_codec.restype=None
    init_codec(C.byref(native_platform),C.byref(native_codec))
    def encode_body(ctx,function,stream,size,payload):
        event(h.read,nw,native,'codec',(function,stream,size,bytes(h.read(payload,size))))
        if function in [0xad230,0xac580,0xaca40]:native_platform.encode(native_platform.context,function,stream,size,payload)
        else:
            assert function==stub
            nw(stream+16,struct.pack('<I',(h.u32(stream+16)+0x3000)&0xffffffff))
    encode_cb=Encode(encode_body);codecs=Codecs(None,encode_cb)
    enqueue=h.lib.h2_message_writer_enqueue
    enqueue.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.POINTER(Ops),C.POINTER(Codecs)]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];enqueue.restype=C.c_uint8
    table=packet+0x3000;destination=packet+0x700;payload=packet+0x800
    for i in range(144):
        h.write(packet,rng.randbytes(0x3800));h.write(scratch,rng.randbytes(0x1828));before=h.read(scratch,0x1828);frames.clear()
        active=i%2;position=[0,8,0x28a0,0x28bf,0x28c0,0x28c1][i//2%6];custom=i%7==0
        h.write(packet+8,struct.pack('<II',endpoint,table));h.write(packet+0x14,bytes([active]));h.write(packet+0x618,struct.pack('<I',0x0a010203));h.write(packet+0x62a,struct.pack('<H',4));h.write(packet+0x62c,struct.pack('<IIIIIII',packet+0x15,0x518,1,1,position,0,0))
        h.write(destination,h.read(packet+0x618,20))
        if i%3==0:h.write(destination,struct.pack('<I',0x0a010204))
        h.write(table+10*32+20,struct.pack('<I',stub if custom else 0xad230));h.write(payload,rng.randbytes(12))
        h.write(endpoint+0x18,struct.pack('<I',socket));h.write(socket,struct.pack('<I',17));h.write(endpoint+0x20,struct.pack('<I',0))
        for off in [0x228,0x3d8]:
            h.write(endpoint+off+0x10,struct.pack('<I',100));h.write(endpoint+off+0x20,struct.pack('<I',100));h.write(endpoint+off+0x28,struct.pack('<I',i%20))
        h.write(0x510548,struct.pack('<II',1,1500));h.write(0x4d8b18,b'\1\1');result=0xffff if i%2 else 1;err=0x2751;mutate=False;original.clear();native.clear();incoming=bytes(28)
        def run_enqueue():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            answer=enqueue(h.memory,C.byref(clock),C.byref(ops),C.byref(codecs),packet,destination,10,12,payload,scratch,workspace)
            if 'packet' in frames:assert h.read(scratch,0x824)==frames['packet_bytes']
            if 'packed' in frames:
                n=h.u32(scratch+0x824);assert h.read(scratch+0x824,4+n)==frames['packed_bytes']
            nw(scratch,before)
            return answer
        answer=h.call('writer_enqueue',0x7b140,{},[packet,destination,10,12,payload],run_enqueue,255)
        assert original==native,(i,original,native)
        assert answer==int(not custom)

    from engine_pools_oracle import STACK
    handle_ping=h.lib.h2_message_handle_ping
    handle_ping.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.POINTER(Ops),C.POINTER(Codecs)]+[C.c_uint32]*5+[C.POINTER(C.c_uint8)];handle_ping.restype=None
    handler=packet+0xa00;reply=packet+0x900
    for i in range(144):
        h.write(packet,rng.randbytes(0x3800));h.write(scratch,rng.randbytes(0x1828));before=h.read(scratch,0x1828);frames.clear()
        h.write(handler+12,struct.pack('<I',packet))
        active=i%2;position=[0,8,0x28a0,0x28bf,0x28c0,0x28c1][i//2%6]
        h.write(packet+8,struct.pack('<II',endpoint,table));h.write(packet+0x14,bytes([active]));h.write(packet+0x618,struct.pack('<I',0x0a010203));h.write(packet+0x62a,struct.pack('<H',4));h.write(packet+0x62c,struct.pack('<IIIIIII',packet+0x15,0x518,1,1,position,0,0))
        h.write(destination,h.read(packet+0x618,20))
        if i%3==0:h.write(destination,struct.pack('<I',0x0a010204))
        h.write(table+32+20,struct.pack('<I',0xac580));h.write(payload,rng.randbytes(12))
        h.write(endpoint+0x18,struct.pack('<I',socket));h.write(socket,struct.pack('<I',17));h.write(endpoint+0x20,struct.pack('<I',0))
        for off in [0x228,0x3d8]:
            h.write(endpoint+off+0x10,struct.pack('<I',100));h.write(endpoint+off+0x20,struct.pack('<I',100));h.write(endpoint+off+0x28,struct.pack('<I',i%20))
        h.write(0x510548,struct.pack('<II',1,1500));h.write(0x4d8b18,b'\1\1');result=0xffff if i%2 else 1;err=0x2751;mutate=False;original.clear();native.clear();incoming=bytes(28)
        reply_before=rng.randbytes(12);h.write(reply,reply_before);h.u.mem_write(STACK+0x8000-12,reply_before)
        def run_ping():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            handle_ping(h.memory,C.byref(clock),C.byref(ops),C.byref(codecs),handler,destination,payload,reply,scratch,workspace)
            assert h.read(reply,12)==bytes(h.u.mem_read(STACK+0x8000-12,12))
            if 'packet' in frames:assert h.read(scratch,0x824)==frames['packet_bytes']
            if 'packed' in frames:
                n=h.u32(scratch+0x824);assert h.read(scratch+0x824,4+n)==frames['packed_bytes']
            nw(scratch,before);nw(reply,reply_before)
        h.call('ping_handler',0x93f60,dict(eax=payload),[handler,destination],run_ping)
        assert original==native,(i,original,native)

    close=h.lib.h2_network_connection_close
    close.argtypes=[C.POINTER(Memory),C.POINTER(ClockOps),C.POINTER(Ops),C.POINTER(Codecs),C.c_void_p]+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];close.restype=None
    for i in range(144):
        h.write(packet,rng.randbytes(0x3800));h.write(scratch,rng.randbytes(0x1828));before=h.read(scratch,0x1828);frames.clear()
        h.write(handler,struct.pack('<II',endpoint,packet));h.write(handler+0x3c,bytes(4));h.write(handler+0x44,struct.pack('<I',1));h.write(handler+0x4c,rng.randbytes(8));h.write(handler+0x54,struct.pack('<I',5));reason=i%18
        active=i%2;position=[0,8,0x28a0,0x28bf,0x28c0,0x28c1][i//2%6]
        h.write(packet+8,struct.pack('<II',endpoint,table));h.write(packet+0x14,bytes([active]));h.write(packet+0x618,struct.pack('<I',0x0a010203));h.write(packet+0x62a,struct.pack('<H',4));h.write(packet+0x62c,struct.pack('<IIIIIII',packet+0x15,0x518,1,1,position,0,0))
        h.write(destination,h.read(packet+0x618,20))
        if i%3==0:h.write(destination,struct.pack('<I',0x0a010204))
        h.write(handler+0x70,h.read(destination,20));h.write(table+7*32+20,struct.pack('<I',0xaca40));h.write(payload,rng.randbytes(12))
        h.write(endpoint+0x18,struct.pack('<I',socket));h.write(socket,struct.pack('<I',17));h.write(endpoint+0x20,struct.pack('<I',0))
        for off in [0x228,0x3d8]:
            h.write(endpoint+off+0x10,struct.pack('<I',100));h.write(endpoint+off+0x20,struct.pack('<I',100));h.write(endpoint+off+0x28,struct.pack('<I',i%20))
        h.write(0x510548,struct.pack('<II',1,1500));h.write(0x4d8b18,b'\1\1');result=0xffff if i%2 else 1;err=0x2751;mutate=False;original.clear();native.clear();incoming=bytes(28)
        reply_before=rng.randbytes(12);h.write(reply,reply_before);h.u.mem_write(STACK+0x8000-12,reply_before)
        def run_close():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            close(h.memory,C.byref(clock),C.byref(ops),C.byref(codecs),None,handler,reason,reply,scratch,workspace)
            assert h.read(reply,12)==bytes(h.u.mem_read(STACK+0x8000-12,12))
            if 'packet' in frames:assert h.read(scratch,0x824)==frames['packet_bytes']
            if 'packed' in frames:
                n=h.u32(scratch+0x824);assert h.read(scratch+0x824,4+n)==frames['packed_bytes']
            nw(scratch,before);nw(reply,reply_before)
        h.call('connection_close_flush',0x88650,dict(esi=handler,edi=reason),[],run_close)
        assert original==native,(i,original,native)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-submit-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_connection.c','include/halo2/network_connection.h','src/message_dispatch.c','include/halo2/message_dispatch.h','tests/message_dispatch_oracle.py','src/network_messages.c','include/halo2/network_messages.h','src/network_packet.c','include/halo2/network_packet.h','src/network_endpoint.c','src/network_routing.c','src/network_send.c','src/network_address.c','tests/network_submit_oracle.py','tests/network_send_oracle.py','tests/network_state_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original connection close through queue overflow/flush and closed-message codec, ping handler/pong response and enqueue with native join-refusal encoder (plus controlled oversized callback cases), address-matching writer flush, raw-datagram construction, packet submission and every engine callee intact; SDK ticks/send/error controlled. Full persistent memory, packed stack bytes, boundary snapshots, clock mutation, loopback, limits and send failures. Guest scratch compared to original stack then restored before persistent comparison; address workspace observed at original send entry. No live Linux networking.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
