#!/usr/bin/env python3
"""Address resolution and datagram observer dispatch with actual engine callees."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from message_dispatch_oracle import NativeCodec,Platform
from network_state_oracle import Operations as Clock
from network_send_oracle import Ops as SendOps,Send,Error
Resolve=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
Status=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32)
class Resolution(C.Structure):
    _fields_=[('context',C.c_void_p),('resolve',Resolve),('prepare',Status)]

def suite(h):
    rng=random.Random(0x783d0);address=h.table;peer=address+0x100;observer=address+0x2000;connections=address+0x4000
    writer=address+0x5000;otherwriter=address+0x5700;table=address+0x6000;local=address+0x7000;sendlocal=address+0x7080;payload=address+0x7200;packet=address+0x8000
    indexout=address+0x40;identity=address+0x50;keyout=address+0x60;endpoint=address+0xa000;socket=address+0xa600;oldaddress=table+0x600
    original=[];native=[];frames={};iteration=0;consumer=0;lookup_seed=bytes(20);send_seed=bytes(80);coverage={}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,*args):
        observed=args[:2]+(bytes(read(args[2],4)),) if kind=='resolve' else args
        events.append((kind,observed,bytes(read(address,0x200)),bytes(read(observer,0x1000)),bytes(read(0x4cf7d4,0x100))))
        if events is original:coverage[kind]=coverage.get(kind,0)+1
        slot=observer+consumer*36
        if iteration%3==0:
            write(slot+0x18,pack(7));write(slot+0x20,pack(0x13572468));write(slot+0x28,pack(0x87654321))
        if iteration%7==0:write(observer+8,pack(otherwriter))
        if kind=='resolve':
            record=(args[1]-0x4cf7dc)//32
            if iteration%5:
                value=[0,0x01020300,0x0102037f,0xffffffff,1][iteration//9%5]
                write(args[2],pack(value))
            return 0 if record==iteration%9 or iteration%4==0 else [1,0xffffffff,0x80004005][iteration%3]
        if kind=='send':return args[2]
        return [0,0,1,0xffffffff][iteration%4]
    resolve=Resolve(lambda ctx,p,k,o:event(h.read,nw,native,'resolve',p,k,o));status=Status(lambda ctx,v:event(h.read,nw,native,'status',v));ops=Resolution(None,resolve,status)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x93100:frames['packet']=((sp-4)&~7)-0x828;return
        if at==0x932f0:frames['packed']=sp-0x1004;return
        if at==0x93182:frames['packet_bytes']=bytes(u.mem_read(frames['packet'],0x824));return
        if at==0x933d6:
            n=u32(u.mem_read,frames['packed']);frames['packed_bytes']=bytes(u.mem_read(frames['packed'],4+n));return
        if at==0xb5110:frames['workspace_seed']=bytes(u.mem_read(sp-28,28));return
        if at==0x7b140:
            label=mode+(':resolved_enqueue' if 'lookup' in frames else ':cached_enqueue');coverage[label]=coverage.get(label,0)+1;return
        if at==0x7adf0:frames['peer']=sp+4;return
        if at==0x7ae67:frames['peer_bytes']=bytes(u.mem_read(frames['peer'],4));return
        if at==0x7acc0:frames['ready']=sp-4;return
        if at==0x7ace4:frames['ready_bytes']=bytes(u.mem_read(frames['ready'],4));return
        if at==0x783d0:frames['lookup']=sp-20;u.mem_write(sp-20,lookup_seed);return
        if at in [0x78472,0x7848d]:frames['lookup_bytes']=bytes(u.mem_read(frames['lookup'],20));return
        if at==0x75e80:
            frames['send']=sp-44;frames['argument']=sp+4;u.mem_write(sp-44,send_seed[:44]);return
        if at in [0x75f34,0x75fac]:
            frames['send_bytes']=bytes(u.mem_read(frames['send'],44))+bytes(u.mem_read(frames['argument'],4));return
        if at==0x3cd254:
            handle,data,n,flags,addr,length=struct.unpack('<6I',u.mem_read(sp+4,24))
            value=event(u.mem_read,u.mem_write,original,'send',handle,bytes(u.mem_read(data,n)),n,flags,bytes(u.mem_read(addr,28)),length);purge=24
        elif at==0x3cd0ec:
            args=struct.unpack('<III',u.mem_read(sp+4,12));value=event(u.mem_read,u.mem_write,original,'resolve',*args);purge=12
        else:value=event(u.mem_read,u.mem_write,original,'status',u32(u.mem_read,sp+4));purge=4
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x93100,0x932f0,0x93182,0x933d6,0xb5110,0x3cd254,0x7b140,0x7adf0,0x7ae67,0x7acc0,0x7ace4,0x783d0,0x78472,0x7848d,0x75e80,0x75f34,0x75fac,0x3cd0ec,0x3cd34f]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    valid=h.lib.h2_network_address_valid;valid.argtypes=[C.POINTER(Memory),C.c_uint32];valid.restype=C.c_uint8
    key=h.lib.h2_network_address_resolve_key;key.argtypes=[C.POINTER(Memory),C.POINTER(Resolution)]+[C.c_uint32]*6;key.restype=C.c_uint8
    search=h.lib.h2_network_address_resolve;search.argtypes=key.argtypes;search.restype=C.c_uint8
    ready=h.lib.h2_network_address_prepare;ready.argtypes=[C.POINTER(Memory),C.POINTER(Resolution)]+[C.c_uint32]*2;ready.restype=C.c_uint8
    lookup=h.lib.h2_network_observer_resolve_address;lookup.argtypes=[C.POINTER(Memory),C.POINTER(Resolution)]+[C.c_uint32]*8;lookup.restype=C.c_uint8
    clock=Clock()
    sendcb=Send(lambda ctx,handle,data,n,flags,addr,length:event(h.read,nw,native,'send',handle,bytes(h.read(data,n)),n,flags,C.string_at(addr,28),length))
    error=Error(lambda ctx:0);send=SendOps(None,sendcb,error);context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    dispatch=h.lib.h2_network_observer_send;dispatch.argtypes=[C.POINTER(Memory),C.POINTER(Clock),C.POINTER(SendOps),C.POINTER(Platform),C.POINTER(Resolution),C.c_void_p]+[C.c_uint32]*10+[C.POINTER(C.c_uint8)];dispatch.restype=None
    enqueue=h.lib.h2_message_writer_enqueue;enqueue.argtypes=[C.POINTER(Memory),C.POINTER(Clock),C.POINTER(SendOps),C.POINTER(Platform)]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];enqueue.restype=C.c_uint8
    register=h.lib.h2_messages_register_session;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    for mode in ['valid','resolve_key','resolve','ready','observer','send_datagram','send_flush']:
        for iteration in range(256 if mode=='send_flush' else 512):
            original.clear();native.clear();frames.clear();h.write(address,rng.randbytes(0x200));h.write(observer,rng.randbytes(0x1000));h.write(connections,rng.randbytes(0x300))
            h.write(0x4cf790,bytes(0x144))
            for i in range(8):
                h.write(0x4cf7d4+i*32,bytes([0 if (iteration+i)%7==0 else 255]));h.write(0x4cf7d8+i*32,pack(1 if (iteration+i)%11==0 else 0))
                h.write(0x4cf7dc+i*32,rng.randbytes(24))
            consumer=iteration%4;slot=observer+consumer*36
            h.write(slot+0x14,pack(0 if iteration%13==0 else 1));h.write(slot+0x18,pack([0,1,7,0xffffffff][iteration//4%4]));h.write(slot+0x1c,pack(0 if iteration%5 else 1))
            for w in [writer,otherwriter]:h.write(w,bytes(0x700));h.write(w+12,pack(table));h.write(w+8,pack(endpoint))
            h.write(endpoint,bytes(0x588));h.write(endpoint+0x18,pack(socket));h.write(socket,pack(17))
            for off in [0x228,0x3d8]:h.write(endpoint+off+0x10,pack(100));h.write(endpoint+off+0x20,pack(100))
            h.write(0x510548,pack(1));h.write(0x51054c,pack(12345));h.write(0x4d8b18,b'\1\1')
            before_packet=rng.randbytes(0x1828);h.write(packet,before_packet)
            h.write(observer+8,pack(writer));h.write(0x4d87d4,pack(connections));h.write(payload,rng.randbytes(16))
            width=[0,4,16,0xffff,5,0x8000][iteration%6]
            h.write(address,bytes(16) if iteration%3==0 else rng.randbytes(16));h.write(address,pack([0,0x00123456,0x7f000001,0xffffffff][iteration//6%4]));h.write(address+18,struct.pack('<H',width))
            if width==16:
                h.write(address,bytes(16))
                if iteration//6%3:h.write(address+(iteration//18%8)*2,b'\1')
            selected=iteration%2;entry=observer+0xa8+selected*0x528;h.write(entry+12,pack(0xffffffff if iteration%17==0 else iteration%2));h.write(entry+0x5c,h.read(address,20))
            local_seed=rng.randbytes(28);send_seed=rng.randbytes(80);h.write(local,local_seed);h.write(sendlocal,send_seed)
            lookup_seed=send_seed[48:68] if mode.startswith('send') else local_seed[:20]
            index=[0,1,7,0xffffffff,0x80000000][iteration//6%5];kind=0 if iteration%5 else 1;port=rng.getrandbits(32)
            value_address=0 if iteration%19==0 else address
            if mode=='send_flush':
                h.write(oldaddress,pack(0xdeadbeef)+bytes(12)+struct.pack('<HH',1001,4))
                for w in [writer,otherwriter]:
                    assert enqueue(h.memory,C.byref(clock),C.byref(send),C.byref(codec),w,oldaddress,9,16,payload,packet,(C.c_uint8*28)())
                    h.write(w,h.read(w,0x700))
                native.clear()
            def finish_resolution(base,incoming):
                expected=frames.get('lookup_bytes',incoming[:20])+frames.get('peer_bytes',incoming[20:24])+frames.get('ready_bytes',incoming[24:28])
                assert h.read(base,28)==expected,(mode,iteration,'resolution scratch')
            def run():
                if mode=='valid':return valid(h.memory,value_address)
                if mode=='resolve_key':result=key(h.memory,C.byref(ops),index,kind,address,peer,port,local)
                elif mode=='resolve':result=search(h.memory,C.byref(ops),index,address,peer,kind,port,local)
                elif mode=='ready':result=ready(h.memory,C.byref(ops),value_address,local)
                elif mode=='observer':result=lookup(h.memory,C.byref(ops),observer,consumer,peer,address,indexout,identity,keyout,local)
                else:
                    dispatch(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(ops),None,observer,selected,consumer,255,9,16,payload,sendlocal,0,packet,(C.c_uint8*28).from_buffer_copy(frames.get('workspace_seed',bytes(28))))
                    assert h.read(sendlocal,48)==frames['send_bytes'],(mode,iteration,'send scratch')
                    finish_resolution(sendlocal+48,send_seed[48:76])
                    if 'packet_bytes' in frames:assert h.read(packet,0x824)==frames['packet_bytes'],(mode,iteration,'packet')
                    if 'packed_bytes' in frames:assert h.read(packet+0x824,len(frames['packed_bytes']))==frames['packed_bytes'],(mode,iteration,'packed')
                    nw(sendlocal,send_seed);nw(packet,before_packet);return
                if mode in ['resolve_key','resolve']:assert h.read(local,4)==frames['peer_bytes'],(mode,iteration,'peer scratch')
                elif mode=='ready':assert h.read(local,4)==frames['ready_bytes'],(mode,iteration,'ready scratch')
                else:finish_resolution(local,local_seed)
                nw(local,local_seed);return result
            addresses={'valid':0x7af40,'resolve_key':0x7adf0,'resolve':0x7ab10,'ready':0x7acc0,'observer':0x783d0,'send_datagram':0x75e80}
            regs={'valid':dict(edx=value_address),'resolve_key':dict(eax=index,edx=kind,esi=address),'resolve':dict(eax=index,ecx=address,ebx=peer),'ready':dict(ecx=value_address),'observer':dict(ecx=observer,eax=consumer,ebx=peer,edi=address),'send_datagram':dict(eax=selected,ecx=255)}
            args={'valid':[],'resolve_key':[peer,port],'resolve':[kind,port],'ready':[],'observer':[indexout,identity,keyout],'send_datagram':[observer,consumer,9,16,payload]}
            for mapping in [addresses,regs,args]:mapping['send_flush']=mapping['send_datagram']
            try:h.call(mode,addresses[mode],regs[mode],args[mode],run,None if mode.startswith('send') else 255)
            except Exception:
                print('mode',mode,'iteration',iteration,'EIP',hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
            assert original==native,(mode,iteration)
    for label in ['resolve','status','send_datagram:resolved_enqueue','send_datagram:cached_enqueue','send_flush:resolved_enqueue','send_flush:cached_enqueue','send']:assert coverage.get(label,0)>0,coverage
    h.resolution_coverage=coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-resolution-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_resolution.c','include/halo2/network_resolution.h','src/network_address.c','src/network_observer_send.c','include/halo2/network_observer.h','src/network_messages.c','src/message_dispatch.c','src/network_packet.c','src/network_routing.c','src/network_send.c','src/network_endpoint.c','tests/network_resolution_oracle.py','tests/hash_crc_oracle.py','tests/message_dispatch_oracle.py','tests/network_state_oracle.py','tests/network_send_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,boundary_coverage=h.resolution_coverage,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Five address/observer resolution routines and datagram observer dispatcher. SDK resolve/status controlled; actual validation, conversion, codec and queue callees. Full memory, scratch and callback snapshots, widths/nulls, key search, SDK failure/unchanged output/zero address, callback slot and writer mutations, cached/fallback address, missing connections. Fresh writers and actual datagram flush/send with captured packet and address scratch; reliable enqueue has separate integration coverage. Not live Linux address resolution or full session shutdown.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
