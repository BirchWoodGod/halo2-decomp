#!/usr/bin/env python3
"""Disconnected-session handler through actual cleanup and migration callees."""
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

from network_session_lifecycle_oracle import Registration, SessionRelease, KeyRelease

class Context(C.Structure):
    _fields_=[('clock',C.POINTER(Clock)),('send',C.POINTER(SendOps)),('codec',C.POINTER(Platform)),('resolution',C.c_void_p),('queue',C.c_void_p),('message',C.c_uint32),('local',C.c_uint32),('reliable',C.c_uint32),('packet',C.c_uint32),('workspace',C.POINTER(C.c_uint8))]

Cleanup=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32)
class Control(C.Structure):
    _fields_=[('messages',C.POINTER(Context)),('registration',C.POINTER(Registration)),('context',C.c_void_p),('callback',Cleanup),('saved',C.c_uint32),('join_message',C.c_uint32),('control_message',C.c_uint32),('handoff',C.c_uint32)]

def suite(h):
    rng=random.Random(0x618d0)
    session=h.table; observer=session+0x8000; writer=session+0xc000; connections=session+0xd000; table=session+0xe000
    endpoint=session+0xe800; socket=session+0xee00; packet=session+0x10000; local=session+0x12000; message=session+0x12100; payload=session+0x12200; oldaddress=session+0x12300
    saved=session+0x12400;join_message=session+0x12500;control_message=session+0x12600;handoff=session+0x12700;owner=session+0x12800;ownervt=owner+0x40
    extra=h.lib.h2_heap_allocate(h.heap,0x15000);assert extra
    storage=extra;wrapper=extra+0x2900;obj=extra+0x2a00;vt=extra+0x2b00;allocations=extra+0x3000;reliable=extra+0x4000
    h.u.mem_map(STACK-0x10000,0x10000)
    migration=session+0x12900;close_local=session+0x12b00;update_payload=session+0x12c00
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
        if kind=='cleanup':
            write(session+0x7650,pack(0xffffffff));write(session+0x72dc+15*20,b'\1');write(session+0x72e0+15*20,pack(2))
            return 0
        if kind in ['session_release','key_release']:
            if iteration%3==0:write(session+0x38,pack(1));write(session+0x10,pack(1))
            return 0xffffffff
        if kind=='poll':return 0
        if kind=='allocate':return allocations+(sum(e[0]=='allocate' for e in events)-1)*32
        if kind=='collect':raise AssertionError('unexpected collection')
        if kind=='ticks':
            if iteration%7==0:
                write(session+0x7488,pack(0x80000000));write(session+0x7420,pack(0x80000000))
                write(0x4cf4a4,pack(0));write(0x4cf4ac,pack(0))
            return (1000+len(events)*10)&0xffffffff
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
    release=SessionRelease(lambda ctx,*args:event(h.read,nw,native,'session_release',*args))
    keyrelease=KeyRelease(lambda ctx,k:event(h.read,nw,native,'key_release',k));registration=Registration(None,release,keyrelease)
    cleanup=Cleanup(lambda ctx,fn,o:event(h.read,nw,native,'cleanup',fn,o))
    control=Control(C.pointer(context),C.pointer(registration),None,cleanup,saved,join_message,control_message,handoff)
    register=h.lib.h2_messages_register_session;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    enqueue=h.lib.h2_message_writer_enqueue;enqueue.argtypes=[C.POINTER(Memory),C.POINTER(Clock),C.POINTER(SendOps),C.POINTER(Platform)]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];enqueue.restype=C.c_uint8
    modes={'tick_migration':(0x61ef0,2)}
    funcs={}
    for name,(_,argc) in modes.items():
        f=getattr(h.lib,'h2_network_session_'+name);f.argtypes=[C.POINTER(Memory),C.POINTER(Control),C.c_void_p]+[C.c_uint32]*argc;f.restype=None;funcs[name]=f
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at in [0x61570,0x62b70,0x63ba0,0x62177]:
            key={0x61570:'transition',0x62b70:'candidate_rebuild',0x63ba0:'peer_lookup',0x62177:'broadcast'}[at];coverage[key]=coverage.get(key,0)+1;return
        if at==0x61ef0:frames['update_payload']=sp-200;return
        if at==0x621e1:frames['update_payload_bytes']=bytes(u.mem_read(frames['update_payload'],200));return
        if at==0x62550:frames['migration_message']=sp-8;return
        if at==0x62626:frames['message_bytes']=bytes(u.mem_read(frames['migration_message'],8));return
        if at==0x616e0:frames['migration']=((sp-4)&~7)-0x118;coverage['migration']=coverage.get('migration',0)+1;return
        if at==0x617aa:frames['migration_bytes']=bytes(u.mem_read(frames['migration'],0x118));return
        if at==0x5a520:coverage['session_cleanup']=coverage.get('session_cleanup',0)+1;return
        if at==0x614a0:frames['handoff']=sp-36;return
        if at==0x61545:frames['handoff_bytes']=bytes(u.mem_read(frames['handoff'],36));return
        if at==0x5a400:frames['control']=sp-52;return
        if at==0x5a4c7:frames['control_bytes']=bytes(u.mem_read(frames['control'],52));return
        if at==0x61180:frames['saved']=sp-112;return
        if at==0x623e0:
            if 'saved' in frames:frames['saved_bytes']=bytes(u.mem_read(frames['saved'],112))
            coverage['resend_join']=coverage.get('resend_join',0)+1
            return
        if at==0x7b140:
            if u32(u.mem_read,sp+12)==9:frames['join_bytes']=bytes(u.mem_read(u32(u.mem_read,sp+20),16))
            return
        if at in [0x62480,0x61450]:
            coverage['resend_leave']=coverage.get('resend_leave',0)+1;frames['message']=sp-8;return
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
        if at==STOP+0xa00:
            value=event(u.mem_read,u.mem_write,original,'cleanup',at,u.reg_read(X.UC_X86_REG_ECX));purge=0
        elif at==0x3cd147:
            value=event(u.mem_read,u.mem_write,original,'session_release',*struct.unpack('<5I',u.mem_read(sp+4,20)));purge=20
        elif at==0x3cd0e1:
            value=event(u.mem_read,u.mem_write,original,'key_release',u32(u.mem_read,sp+4));purge=4
        elif at in [STOP+0x800,STOP+0x900]:
            kind='poll' if at==STOP+0x800 else 'allocate';purge=4 if kind=='poll' else 12
            args=struct.unpack('<'+'I'*(purge//4),u.mem_read(sp+4,purge))
            value=event(u.mem_read,u.mem_write,original,kind,at,u.reg_read(X.UC_X86_REG_ECX),*args)
        elif at==0x3314b0:value=event(u.mem_read,u.mem_write,original,'ticks');purge=0
        else:
            handle,data,n,flags,addr,length=struct.unpack('<6I',u.mem_read(sp+4,24))
            value=event(u.mem_read,u.mem_write,original,'send',handle,bytes(u.mem_read(data,n)),n,flags,bytes(u.mem_read(addr,28)),length);purge=24
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x61570,0x62b70,0x63ba0,0x62177,0x61ef0,0x621e1,0x62550,0x62626,0x616e0,0x617aa,0x5a520,0x614a0,0x61545,0x5a400,0x5a4c7,0x61180,0x623e0,0x7b140,STOP+0xa00,0x3cd147,0x3cd0e1,0x62480,0x61450,0x6251e,0x61477,0x75e80,0x75f34,0x75fac,0x95580,0x95835,0xb5110,0x3314b0,0x3cd254,STOP+0x800,STOP+0x900]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    for mode,(address,_) in modes.items():
        for iteration in range(1024):
            original.clear();native.clear();frames.clear();h.write(session,rng.randbytes(0x7900));h.write(observer,bytes(0x3000));h.write(connections,bytes(0x400))
            h.write(extra,bytes(0x15000));h.write(storage,pack(vt));h.write(storage+12,pack(table));h.write(storage+20,pack(32));h.write(vt+4,pack(STOP+0x800));h.write(vt+0x14,pack(STOP+0x900));h.write(wrapper,pack(obj));h.write(obj,pack(vt));h.write(0x4d87f8,pack(wrapper));h.write(0x4d87dc,pack(storage))
            h.write(session+8,pack(observer));h.write(session+0x10,pack(0));h.write(session+0x40,pack(iteration%3));h.write(session+0x54,pack([0,1,2,3,0xffffffff,0x80000000][iteration%6]))
            h.write(0x4d87d4,pack(connections));h.write(0x510548,pack(iteration%2));h.write(0x51054c,pack(1000));h.write(0x4cf4b0,pack([0,10,100,0xffffffff,0x80000000][iteration%5]));h.write(0x4d8b18,b'\1\1')
            h.write(session+0x7424,pack([0xffffffff,0,999,1000,1001,0x80000000][iteration//5%6]))
            h.write(session+0x741c,pack(9));h.write(session+0x4c,pack(0xffffffff if iteration%7==0 else 1));h.write(session+0x48,bytes([iteration%17==0]));h.write(session+0x7420,bytes([iteration%13==0]))
            h.write(session+0x24,bytes([iteration%3!=0]));h.write(session+0x38,pack(0));h.write(session+0x78a8,pack(0 if iteration%7==0 else owner));h.write(owner,pack(ownervt));h.write(ownervt+8,pack(STOP+0xa00))
            h.write(0x4cf8d4,b'\1');h.write(0x4cf7d4,bytes(64));h.write(0x4cf7d4,b'\1');h.write(0x4cf7f4,b'\1');h.write(0x4cf4a0,pack(0));h.write(session+4,pack(writer))
            h.write(session+0x7448,pack(0x7f000002)+bytes(12)+struct.pack('<HH',1000,4));h.write(session+0x72d8,pack(iteration%16))

            for i in range(16):h.write(session+0x72dc+i*20,bytes(20));h.write(session+0x72e0+i*20,pack(0xffffffff))
            for i in range(3):
                peer=session+0x72dc+i*20;entry=observer+0xa8+i*0x528
                h.write(peer,bytes([iteration%5!=0]));h.write(peer+1,bytes([0 if (iteration+i)%7==0 else 255]));h.write(peer+4,pack(i));h.write(entry,pack(7 if (iteration+i)%2 else 6));h.write(entry+12,pack(0xffffffff if (iteration+i)%11==0 else i));h.write(connections+i*0xf8,pack(endpoint));h.write(connections+i*0xf8+0x54,pack(2 if iteration%4==0 else 3))
                h.write(entry+0x5c,pack(0x7f000001+i)+bytes(12)+struct.pack('<HH',1000,4))
            h.write(writer,bytes(0x700));h.write(writer+12,pack(table));h.write(writer+8,pack(endpoint));h.write(observer+8,pack(writer))
            h.write(endpoint,bytes(0x588));h.write(endpoint+0x18,pack(socket));h.write(socket,pack(17))
            for off in [0x228,0x3d8]:h.write(endpoint+off+0x10,pack(100));h.write(endpoint+off+0x20,pack(100))
            h.write(payload,rng.randbytes(8));h.write(oldaddress,pack(0xdeadbeef)+bytes(12)+struct.pack('<HH',1001,4))
            seeds={update_payload:rng.randbytes(200),migration:rng.randbytes(0x118),close_local:rng.randbytes(12),local:rng.randbytes(80),message:rng.randbytes(8),packet:rng.randbytes(0x1828),reliable:bytes(0x10037),saved:rng.randbytes(112),join_message:rng.randbytes(16),control_message:rng.randbytes(52),handoff:rng.randbytes(36)}
            for p,b in seeds.items():h.write(p,b)
            C.memset(workspace,0,28)
            assert enqueue(h.memory,C.byref(clock),C.byref(send),C.byref(codec),writer,oldaddress,11,8,payload,packet,workspace)
            h.write(writer,h.read(writer,0x700));native.clear()
            previous=[0,999,1000,1001,0xfffffff0,0x80000000][iteration//2%6]
            limit=[0,10,1000,0xffffffff,0x80000000,0x7fffffff][iteration//12%6]
            h.write(session+0x7488,pack(previous))
            h.write(0x4cf4a4,pack(limit));h.write(0x4cf4ac,pack(limit))
            h.write(session+0x748c,pack([0,1000,1001,0xffffffff][iteration%4]))
            h.write(session+0x7444,pack(0x7f000002)+bytes(12)+struct.pack('<HH',1000,4))
            h.write(session+0x54,pack(iteration%4));h.write(session+0x72d8,pack(iteration%3))
            h.write(session+0x7420,pack([0,999,1000,1001,0xfffffff0,0x80000000][iteration%6]))
            h.write(session+0x7424,pack([0,1,999,1000,0xffffffff][iteration//6%5]))
            h.write(session+0x7428,pack([0,1000,1001,0x80000000][iteration//30%4]))
            h.write(session+0x742c,pack(iteration//4%3))
            h.write(session+0x7430,bytes(192));h.write(session+0x7484,pack(iteration%4))
            h.write(session+0x74ec,pack([0,1,7,0xffffffff][iteration%4]))
            h.write(session+0x74f0,pack([0,1,7][iteration%3]));h.write(session+0x74f4,pack([0,2,7][iteration//3%3]))
            for i in range(3):h.write(session+0x74f8+i*4,pack([0,999,1000,1001][(iteration+i)%4]))
            for off in [0x4cf4cc,0x4cf4d0,0x4cf4d4,0x4cf4c8]:h.write(off,pack([0,1,1000,0xffffffff,0x7fffffff][iteration//5%5]))
            regs={mode:{}};args=[session];nativeargs=[session,update_payload]
            def run():
                funcs[mode](h.memory,C.byref(control),None,*nativeargs)
                assert h.read(update_payload,200)==frames.get('update_payload_bytes',seeds[update_payload]),(iteration,'update payload')
                assert h.read(message,8)==frames.get('message_bytes',seeds[message]),(mode,iteration,'message scratch')
                assert h.read(local,48)==frames.get('local_bytes',seeds[local][:48]),(mode,iteration,'dispatcher scratch')
                assert h.read(reliable,0x10037)==frames.get('reliable_bytes',seeds[reliable]),(mode,iteration,'reliable scratch')
                for p,key,n in [(saved,'saved_bytes',112),(join_message,'join_bytes',16),(control_message,'control_bytes',52),(handoff,'handoff_bytes',36)]:
                    assert h.read(p,n)==frames.get(key,seeds[p]),(mode,iteration,key)
                for p,b in seeds.items():nw(p,b)
            try:h.call(mode,address,regs[mode],args,run,None)
            except Exception:
                print('mode',mode,'iteration',iteration,'eip',hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
            assert original==native,(mode,iteration,'events')
    assert all(coverage.get(k) for k in ['ticks','session_cleanup','transition','candidate_rebuild','peer_lookup','broadcast']),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-migration-update-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_session_migration_transition.c','src/network_session_migration_send.c','src/network_session_snapshot_reset.c','src/network_session_host_entry.c','src/network_session_peer_lookup.c','src/network_session_migration_start.c','src/network_session_migration_payload.c','src/network_observer_admission.c','src/network_connection.c','src/network_session_migration_update.c','include/halo2/network_session_migration_update.h','tests/network_session_migration_update_oracle.py','src/network_session_control.c','include/halo2/network_session_control.h','src/network_session_lifecycle.c','tests/network_session_control_oracle.py','tests/network_session_lifecycle_oracle.py','src/network_observer_send.c','src/network_storage_queue.c','src/network_resolution.c','src/message_dispatch.c','src/network_messages.c','src/network_packet.c','src/network_send.c','src/network_endpoint.c','src/network_session_send.c','include/halo2/network_session_send.h','tests/network_session_send_oracle.py','tests/network_storage_queue_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py','tests/network_send_oracle.py','tests/message_dispatch_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Migration controller through actual peer lookup, candidate rebuild, transition, sender and cleanup. Full memory, callbacks, original200-byte payload and nested scratch. Controlled SDK/virtual boundaries; bounded peers with inactive connection-request states. No live migration or game startup.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
