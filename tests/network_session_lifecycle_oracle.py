#!/usr/bin/env python3
"""Session lifecycle instructions with native message codec/queue/packet callees."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops,Send,Error
from message_dispatch_oracle import NativeCodec,Platform
SessionRelease=C.CFUNCTYPE(C.c_uint32,C.c_void_p,*([C.c_uint32]*5))
KeyRelease=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32)
class Registration(C.Structure):
    _fields_=[('context',C.c_void_p),('session_release',SessionRelease),('key_release',KeyRelease)]

def suite(h):
    rng=random.Random(0x61180);session=h.table;observer=session+0x8000;other=session+0xd000
    writer=session+0x12500;otherwriter=session+0x12c00;table=session+0x13400;address=table+0x600
    saved=session+0x14000;local=session+0x14100;endpoint=session+0x14200;socket=session+0x14900;packet=session+0x15000
    original=[];native=[];iteration=0;mode='';now=0;seed=b'';frames={};workspace_seed=bytes(28);coverage={}
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,*args):
        if events is original:coverage[mode+':'+kind]=coverage.get(mode+':'+kind,0)+1
        events.append((kind,args,bytes(read(session,0x78b8)),bytes(read(observer,0x5000)),bytes(read(other,0x5000)),bytes(read(writer,0xe00)),bytes(read(0x4cf7d4,0x80))))
        if kind=='ticks':
            number=sum(e[0]=='ticks' for e in events)
            if iteration%3==0 and number==1:
                write(session+0x748c,pack(now));write(session+0x1c,pack(0x12345678));write(session+0x747c,pack(0xabcdef01))
                write(session+8,pack(other));write(session+4,pack(otherwriter))
                write(session+0x7424,pack(0xface1234));write(session+0x75dc,pack(0xface5678))
                write(session+0x7650,pack(0xffffffff));write(session+0x72dc+15*20,b'\1')
                write(0x4cf4a0,pack([0,100,0xffffffff][iteration//3%3]))
            if iteration%11==0 and number==1:
                write(0x510548,b'\1');write(0x51054c,pack(now+17))
            return (now+number-1)&0xffffffff
        if kind=='session_release' and iteration%3==0:
            write(session+0x38,pack(2));write(session+8,pack(other));write(session+0x10,pack(3))
            write(0x4cf7d4+64,b'\1')
        if kind=='key_release' and iteration%3==0:
            write(session+0x38,pack(3));write(session+8,pack(other));write(session+0x10,pack(2))
            write(args[0]-8,b'\x7f');write(session+0x24,b'\0')
        if kind=='send':
            if iteration%5==0:write(0x510548,b'\1');write(0x51054c,pack(now+29))
            return args[2]
        return [0,1,0xffffffff,0x80004005][iteration%4]
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks'));clock=Operations(None,tick,Provider())
    sendcb=Send(lambda ctx,handle,data,n,flags,addr,length:event(h.read,nw,native,'send',handle,bytes(h.read(data,n)),n,flags,C.string_at(addr,28),length))
    error=Error(lambda ctx:0);send=Ops(None,sendcb,error)
    release=SessionRelease(lambda ctx,*args:event(h.read,nw,native,'session_release',*args));key=KeyRelease(lambda ctx,arg:event(h.read,nw,native,'key_release',arg));registration=Registration(None,release,key)
    context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    def hook(u,at,size,ctx):
        nonlocal workspace_seed
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x61180:frames['saved']=sp-112;return
        if at==0x623e0:frames['local']=sp-16;u.mem_write(sp-16,seed);return
        if at==0x93100:frames['packet']=((sp-4)&~7)-0x828;return
        if at==0x932f0:frames['packed']=sp-0x1004;return
        if at==0x93182:frames['packet_bytes']=bytes(u.mem_read(frames['packet'],0x824));return
        if at==0x933d6:
            n=u32(u.mem_read,frames['packed']);frames['packed_bytes']=bytes(u.mem_read(frames['packed'],4+n));return
        if at==0xb5110:workspace_seed=bytes(u.mem_read(sp-28,28));return
        if at==0x3314b0:value=event(u.mem_read,u.mem_write,original,'ticks');purge=0
        elif at==0x3cd147:
            args=struct.unpack('<5I',u.mem_read(sp+4,20));value=event(u.mem_read,u.mem_write,original,'session_release',*args);purge=20
        elif at==0x3cd0e1:value=event(u.mem_read,u.mem_write,original,'key_release',u32(u.mem_read,sp+4));purge=4
        else:
            handle,data,n,flags,addr,length=struct.unpack('<6I',u.mem_read(sp+4,24));value=event(u.mem_read,u.mem_write,original,'send',handle,bytes(u.mem_read(data,n)),n,flags,bytes(u.mem_read(addr,28)),length);purge=24
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x61180,0x623e0,0x93100,0x932f0,0x93182,0x933d6,0xb5110,0x3314b0,0x3cd147,0x3cd0e1,0x3cd254]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    detach=h.lib.h2_network_session_detach_peer;detach.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];detach.restype=None
    unregister=h.lib.h2_network_session_release_registration;unregister.argtypes=[C.POINTER(Memory),C.POINTER(Registration),C.c_uint32];unregister.restype=None
    common=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform)]
    update=h.lib.h2_network_session_update_join_abort;update.argtypes=common+[C.c_uint32]*3+[C.POINTER(C.c_uint8)];update.restype=None
    begin=h.lib.h2_network_session_begin_join_abort;begin.argtypes=common+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];begin.restype=None
    enqueue=h.lib.h2_message_writer_enqueue;enqueue.argtypes=common+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];enqueue.restype=C.c_uint8
    register=h.lib.h2_messages_register_session;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    for mode in ['detach','registration','update','begin','update_flush','begin_flush']:
        for iteration in range(256 if 'flush' in mode else 512):
            original.clear();native.clear();frames.clear();workspace_seed=bytes(28);seed=rng.randbytes(16)
            h.write(session,rng.randbytes(0x78b8));h.write(observer,rng.randbytes(0x5000));h.write(other,rng.randbytes(0x5000))
            for w in [writer,otherwriter]:h.write(w,bytes(0x700));h.write(w+12,pack(table));h.write(w+8,pack(endpoint))
            h.write(endpoint,bytes(0x588));h.write(endpoint+0x18,pack(socket));h.write(socket,pack(17))
            for off in [0x228,0x3d8]:h.write(endpoint+off+0x10,pack(100));h.write(endpoint+off+0x20,pack(100))
            h.write(0x4d8b18,b'\1\1');h.write(0x4cf7d4,rng.randbytes(0x80));h.write(0x4cf8d4,bytes([iteration%2]))
            h.write(session+4,pack(writer));h.write(session+8,pack(observer))
            consumer=[0,1,3,7,8,31,32,63,0xffffffff][iteration%9] if mode=='detach' else iteration%4
            h.write(session+0x10,pack(consumer));h.write(session+0x38,pack(iteration%4));h.write(session+0x24,bytes([0 if iteration%5==0 else 255]))
            h.write(session+0x741c,pack([0,1,2,3,4,5,6,7,8,9,10,0xffffffff][iteration%12]))
            for i in range(16):
                h.write(session+0x72dc+i*20,bytes([0 if (iteration+i)%3 else 1]));h.write(session+0x72dc+i*20+4,pack(0xffffffff if (iteration+i)%5==0 else i%15))
            now=[0,1,100,1000,0x7fffffff,0x80000000,0xfffffffe,0xffffffff][iteration%8]
            elapsed=[0,99,100,101,0xffffffff,0x80000000,0x7fffffff][iteration//8%7]
            threshold=[100,0,0xffffffff,0x7fffffff,0x80000000][iteration//56%5]
            h.write(0x510548,bytes([iteration//7%2]));h.write(0x51054c,pack(now));h.write(0x4cf4a0,pack(threshold));h.write(session+0x748c,pack(now-elapsed))
            addr=pack(0x00123456)+rng.randbytes(12)+struct.pack('<HH',1001,4)
            h.write(session+(0x7448 if mode.startswith('begin') else 0x7444),addr)
            h.write(address,pack(0xdeadbeef)+bytes(12)+struct.pack('<HH',1001,4))
            h.write(local,seed);h.write(saved,rng.randbytes(112));before_saved=h.read(saved,112)
            h.write(packet,rng.randbytes(0x1828));before_packet=h.read(packet,0x1828)
            if 'flush' in mode:
                for w in [writer,otherwriter]:
                    assert enqueue(h.memory,C.byref(clock),C.byref(send),C.byref(codec),w,address,9,16,local,packet,(C.c_uint8*28)())
                    h.write(w,h.read(w,0x700))
                native.clear()
            def run():
                workspace=(C.c_uint8*28).from_buffer_copy(workspace_seed)
                if mode.startswith('begin'):begin(h.memory,C.byref(clock),C.byref(send),C.byref(codec),session,saved,local,packet,workspace)
                else:update(h.memory,C.byref(clock),C.byref(send),C.byref(codec),session,local,packet,workspace)
                assert h.read(local,16)==bytes(h.u.mem_read(frames['local'],16)),(mode,iteration,'message scratch')
                if mode.startswith('begin'):assert h.read(saved,112)==bytes(h.u.mem_read(frames['saved'],112)),(mode,iteration,'saved scratch')
                if 'packet_bytes' in frames:assert h.read(packet,0x824)==frames['packet_bytes'],(mode,iteration,'packet')
                if 'packed_bytes' in frames:assert h.read(packet+0x824,len(frames['packed_bytes']))==frames['packed_bytes'],(mode,iteration,'packed')
                nw(local,seed);nw(saved,before_saved);nw(packet,before_packet)
            try:
                if mode=='detach':h.call(mode,0x5f970,dict(edi=session,edx=iteration%16),[],lambda:detach(h.memory,session,iteration%16))
                elif mode=='registration':h.call(mode,0x5fb60,dict(esi=session),[],lambda:unregister(h.memory,C.byref(registration),session))
                else:h.call(mode,0x61180 if mode.startswith('begin') else 0x623e0,dict(ebx=session) if mode.startswith('begin') else dict(esi=session),[],run)
            except Exception:
                print('mode',mode,'iteration',iteration,'EIP',hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
            assert original==native,(mode,iteration,[(e[0],e[1]) for e in original],[(e[0],e[1]) for e in native])
    for key in ['registration:session_release','registration:key_release','update:ticks','begin:ticks','update_flush:send','begin_flush:send']:assert coverage.get(key,0)>0,(key,coverage)
    h.lifecycle_coverage=coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-lifecycle-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_session_lifecycle.c','include/halo2/network_session_lifecycle.h','src/network_messages.c','src/message_dispatch.c','src/network_packet.c','src/network_routing.c','src/network_send.c','src/network_endpoint.c','tests/network_session_lifecycle_oracle.py','tests/message_dispatch_oracle.py','tests/network_state_oracle.py','tests/network_send_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,boundary_coverage=h.lifecycle_coverage,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Peer detach, session registration release, join-abort timer and transition. Original message codec, queue/flush, packet construction, statistics and socket helpers intact. SDK clock/send/registration calls controlled. Full persistent memory and boundary snapshots, saved stack scratch, callback pointer/timestamp mutations, shift masks, signed wrapping times, fresh queues and actual flush/send integration. No complete session state machine or Linux networking backend.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
