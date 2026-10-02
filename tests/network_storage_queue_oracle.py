#!/usr/bin/env python3
"""Reliable fragmentation against x86; virtual provider methods remain boundaries."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STACK,STOP
from data_array_oracle import ROOT,Memory,EXPECTED
from message_dispatch_oracle import NativeCodec,Platform,Encode
from network_state_oracle import Operations,Ticks,Provider
from network_storage_oracle import Operations as ClearOps,Lookup,Release
Poll=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
Allocate=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
Collect=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class QueueOps(C.Structure):
    _fields_=[('context',C.c_void_p),('poll',Poll),('allocate',Allocate),('collect',Collect)]

def suite(h):
    rng=random.Random(0x95580);storage=h.table;wrapper=storage+0x2900;other=wrapper+0x20
    obj=storage+0x2a00;altobj=obj+0x40;vt=storage+0x2b00;altvt=vt+0x40;svt=storage+0x2c00
    allocations=storage+0x3000;table=storage+0x4000;payload=storage+0x5000;scratch=storage+0x8000
    original=[];native=[];iteration=0;scenario=0;seed=b'';frame=0;coverage={};custom=False;clear_frame=0;clear_seed=bytes(8);clear_scratch=storage+0x7200;observer=storage+0x6000;connections=storage+0x7000;sendlocal=storage+0x7300;send_seed=bytes(80);observer_mode=False
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,*args):
        number=1+sum(e[0]==kind for e in events)
        events.append((kind,args,bytes(read(storage,0x4000)),bytes(read(0x4d87f8,4))))
        if events is original:coverage[kind]=coverage.get(kind,0)+1
        if kind=='poll':
            if scenario==1 or (scenario==2 and number==3) or (scenario in [6,7] and number==5):return 0xff
            if scenario==3 and number>=2:
                write(storage+28,bytes(read(storage+24,4)));write(storage+40,pack(0));write(storage+36,pack(0))
            if scenario==8:
                # Valid queue can move while callback executes; reread bounds and origins.
                write(storage+28,bytes(read(storage+24,4)));write(storage+36,pack(number%8));write(storage+40,pack(0))
            # Model a consumer draining to avoid stalls once longer messages fill the ring.
            if scenario not in [3,7] and ((u32(read,storage+24)-u32(read,storage+28))&0xffffffff)>=u32(read,storage+20):
                write(storage+28,bytes(read(storage+24,4)));write(storage+36,pack(0));write(storage+40,pack(0))
            if number>100:raise AssertionError('unexpected unbounded retry')
            return 0
        if kind=='allocate':
            if scenario in [4,5,6] and number==1:
                write(0x4d87f8,pack(other));write(wrapper,pack(altobj));write(wrapper+4,pack(0xffffffff))
            fail=scenario==6 or (scenario==4 and number==1) or (scenario==5 and number<=2)
            if fail:return 0
            if scenario==8:
                write(storage+36,pack((number+2)%8));write(wrapper+4,pack(0xfffffffe))
            return allocations+((number-1)%64)*32
        if kind=='collect':
            if scenario in [4,5,6]:write(wrapper,pack(obj));write(other,pack(altobj))
        if kind=='lookup':return 255
        if kind=='release':write(args[2],bytes(32))
        if kind=='ticks':return (0xfffffff0+iteration)&0xffffffff
        return 0
    poll=Poll(lambda ctx,fn,o,v:event(h.read,nw,native,'poll',fn,o,v))
    allocate=Allocate(lambda ctx,fn,o,n,a,b:event(h.read,nw,native,'allocate',fn,o,n,a,b))
    collect=Collect(lambda ctx,fn,o,v:event(h.read,nw,native,'collect',fn,o,v));ops=QueueOps(None,poll,allocate,collect)
    def native_lookup(ctx,function,object,handle,output):
        value=event(h.read,nw,native,'lookup',function,object,handle,output-clear_scratch)
        nw(output,pack(0x87654321));return value
    lookup=Lookup(native_lookup)
    release=Release(lambda ctx,f,o,hnd,v:event(h.read,nw,native,'release',f,o,hnd,v));clear_ops=ClearOps(None,lookup,release)
    clear=h.lib.h2_network_storage_clear;clear.argtypes=[C.POINTER(Memory),C.POINTER(ClearOps),C.c_uint32,C.c_uint32];clear.restype=None
    ticks=Ticks(lambda ctx:event(h.read,nw,native,'ticks'));clock=Operations(None,ticks,Provider())
    context=NativeCodec(h.memory,C.pointer(clock),storage+0x7100);actual=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(actual),C.byref(context))
    bulk=h.lib.h2_bitstream_write_buffer;bulk.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3
    stub=STOP+0xc00
    def encode_call(ctx,function,stream,size,data):
        if function==stub:
            nw(stream+8,pack([1,2,4,8,0xfffffffc][iteration//9%5]));bulk(h.memory,stream,data,size)
        else:actual.encode(actual.context,function,stream,size,data)
    encode=Encode(encode_call);codec=Platform(None,encode)
    # Synthetic boundary codec tail work uses the original bulk writer unchanged.
    code=bytes.fromhex('8b5424048b44240c8b4c240851')+b'\xe8'+struct.pack('<i',0x1955d0-(stub+18))+bytes.fromhex('c20c00')
    h.u.mem_write(stub,code);h.u.mem_map(STACK-0x10000,0x10000)
    def hook(u,at,size,ctx):
        nonlocal frame,clear_frame
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x75e80:u.mem_write(sp-44,send_seed[:44]);return
        if at==stub:u.mem_write(u32(u.mem_read,sp+4)+8,pack([1,2,4,8,0xfffffffc][iteration//9%5]));return
        if at==0x94bf0:clear_frame=sp-8;u.mem_write(clear_frame,clear_seed);return
        if at==0x95580:
            frame=((sp-4)&~7)-0x10054-12+0x24;u.mem_write(frame,seed);return
        if at==0x3314b0:value=event(u.mem_read,u.mem_write,original,'ticks');purge=0
        else:
            objarg=u.reg_read(X.UC_X86_REG_ECX)
            if at in [STOP+0xb00,STOP+0xb10]:
                hnd,out=struct.unpack('<II',u.mem_read(sp+4,8));kind='lookup' if at==STOP+0xb00 else 'release'
                args=(at,objarg,hnd,out-clear_frame if kind=='lookup' else out);purge=8
            elif at in [STOP+0x800,STOP+0x810]:kind='poll';args=(at,objarg,u32(u.mem_read,sp+4));purge=4
            elif at in [STOP+0x900,STOP+0x910]:kind='allocate';args=(at,objarg,*struct.unpack('<III',u.mem_read(sp+4,12)));purge=12
            else:kind='collect';args=(at,objarg,u32(u.mem_read,sp+4));purge=4
            value=event(u.mem_read,u.mem_write,original,kind,*args)
            if kind=='lookup':u.mem_write(out,pack(0x87654321))
        u.reg_write(X.UC_X86_REG_EAX,value or 0);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x75e80,stub,0x94bf0,STOP+0xb00,STOP+0xb10,0x95580,0x3314b0,STOP+0x800,STOP+0x810,STOP+0x900,STOP+0x910,STOP+0xa00,STOP+0xa10]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_storage_enqueue;fn.argtypes=[C.POINTER(Memory),C.POINTER(QueueOps),C.POINTER(Platform)]+[C.c_uint32]*5;fn.restype=None
    dispatch=h.lib.h2_network_observer_send;dispatch.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_void_p,C.POINTER(Platform),C.c_void_p,C.POINTER(QueueOps)]+[C.c_uint32]*10+[C.POINTER(C.c_uint8)];dispatch.restype=None
    descriptors=[d for group in json.loads((ROOT/'config/message_descriptors.json').read_text())['functions'] for d in group['descriptors'] if d['index']<25 and d['index']!=3]
    h.write(table,bytes(0x5a0))
    for name in ['discovery','connection','session']:
        register=getattr(h.lib,'h2_messages_register_'+name);register.argtypes=[C.POINTER(Memory),C.c_uint32];register(h.memory,table)
    h.write(table,h.read(table,0x5a0));h.write(table+30*32+20,pack(stub))
    for mode in ['native','boundary','observer']:
        custom=mode!='native';observer_mode=mode=='observer'
        for iteration in range(512 if observer_mode else 384 if custom else 768):
            original.clear();native.clear();scenario=iteration%9;frame=0
            seed=rng.randbytes(0x10037);h.write(scratch,seed);h.write(storage,rng.randbytes(0x4000));h.write(payload,rng.randbytes(0x2000))
            h.write(storage,pack(svt));h.write(svt+4,pack(STOP+0x800));h.write(storage+12,pack(table))
            h.write(vt+0x14,pack(STOP+0x900));h.write(vt+0x28,pack(STOP+0xa00));h.write(altvt+0x14,pack(STOP+0x910));h.write(altvt+0x28,pack(STOP+0xa10))
            for v in [vt,altvt]:h.write(v,pack(STOP+0xb10));h.write(v+4,pack(STOP+0xb00))
            h.write(obj,pack(vt));h.write(altobj,pack(altvt));h.write(wrapper,struct.pack('<II',obj,0xffffffff if iteration%2 else 0));h.write(other,struct.pack('<II',altobj,7));h.write(0x4d87f8,pack(wrapper))
            base=[0,1,100,0xfffffff0,0x7fffff00][iteration//9%5]
            h.write(storage+20,pack(8));h.write(storage+24,pack(base+(8 if scenario in [3,7] else 0)));h.write(storage+28,pack(base))
            h.write(storage+36,pack([0,1,7,8][iteration//45%4]));h.write(storage+40,pack(0));h.write(storage+0x2848,pack([0,1,0xfffffff0][iteration%3]))
            h.write(0x510550,pack(0));h.write(0x55e755,bytes([iteration%2]))
            if custom:
                index=30;size=[0,1,7,8,199,200,201,455,456,457,1024,4096][iteration//9%12]
            else:
                descriptor=descriptors[iteration//9%len(descriptors)];index=descriptor['index'];size=descriptor['words'][2]
                if index==8:
                    h.write(payload+12,pack(iteration%17));h.write(payload+0x160,pack(iteration%3))
                if index==22:h.write(payload+0x5c,pack(iteration%17))
                if index==24:h.write(payload+24,struct.pack('<H',iteration%2))
            cycle=not custom and scenario==0
            if cycle:
                h.write(storage+4,b'\1');h.write(storage+20,pack(32));h.write(storage+36,pack(0));h.write(storage+0x2848,pack(0));h.write(wrapper+4,pack(0))
                h.write(storage+0x1834,bytes(8))
            if not custom and index==9 and iteration%2 and not cycle:h.write(storage+36,pack(0xfffffff8))
            if observer_mode:
                index=[0,31,32,63,64,65,255,256,257][iteration//54%9]
                h.write(table+index*32+20,pack(stub))
                identifier=0xffffffff if iteration%17==0 else iteration%2
                h.write(observer+0xa8+12,pack(identifier));h.write(0x4d87d4,pack(connections));h.write(0x4d87dc,pack(storage))
                conn=connections+(iteration%2)*0xf8
                h.write(conn+0x54,pack([0,2,3,5,0xffffffff,0x80000000][iteration//9%6]));h.write(conn+0x14,pack(0))
                send_seed=rng.randbytes(80);h.write(sendlocal,send_seed)
            def run():
                if observer_mode:
                    dispatch(h.memory,C.byref(clock),None,C.byref(codec),None,C.byref(ops),observer,0,0,0,index,size,payload,sendlocal,scratch,0,(C.c_uint8*28)())
                    expected_local=bytes(h.u.mem_read(STACK+0x8000-44,44))+bytes(h.u.mem_read(STACK+0x8004,4))
                    assert h.read(sendlocal,48)==expected_local,(iteration,'observer scratch')
                    nw(sendlocal,send_seed)
                else:fn(h.memory,C.byref(ops),C.byref(codec),storage,index,size,payload,scratch)
                if frame:
                    expected=bytearray(h.u.mem_read(frame,len(seed)));expected[:4]=pack(scratch+0x38)
                    assert h.read(scratch,len(seed))==expected,(custom,iteration,'scratch')
                else:assert h.read(scratch,len(seed))==seed
                nw(scratch,seed)
            try:
                if observer_mode:h.call('observer_reliable',0x75e80,dict(eax=0,ecx=0),[observer,0,index,size,payload],run)
                else:h.call('boundary_codec' if custom else 'native_codec',0x95580,{},[storage,index,size,payload],run)
            except Exception:
                print('custom',custom,'iteration',iteration,'scenario',scenario,'type',index,'size',size,'EIP',hex(h.u.reg_read(X.UC_X86_REG_EIP)),'events',[(e[0],e[1]) for e in original[-3:]]);raise
            assert original==native,(custom,iteration,[(e[0],e[1]) for e in original],[(e[0],e[1]) for e in native])
            if cycle:
                assert h.u32(wrapper+4)>0
                original.clear();native.clear();clear_seed=rng.randbytes(8);h.write(clear_scratch,clear_seed)
                def run_clear():
                    clear(h.memory,C.byref(clear_ops),storage,clear_scratch)
                    assert h.read(clear_scratch,8)==bytes(h.u.mem_read(clear_frame,8)),iteration
                    nw(clear_scratch,clear_seed)
                h.call('enqueue_then_clear',0x94bf0,dict(esi=storage),[],run_clear)
                assert original==native,(iteration,'clear events')
                assert h.u32(wrapper+4)==0 and h.u32(storage+0x2848)==0,(iteration,'release accounting')
    for kind in ['poll','allocate','collect','ticks','lookup','release']:assert coverage.get(kind,0)>0,coverage
    h.queue_coverage=coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-storage-queue-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_storage_queue.c','src/network_observer_send.c','include/halo2/network_observer.h','src/network_storage.c','include/halo2/network_storage.h','src/network_messages.c','src/bitstream.c','src/message_dispatch.c','src/crc.c','tests/network_storage_queue_oracle.py','tests/network_storage_oracle.py','tests/hash_crc_oracle.py','tests/message_dispatch_oracle.py','tests/network_state_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,boundary_coverage=h.queue_coverage,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Reliable storage enqueue with original stack probe, header, codec, bitstream and CRC instructions. Virtual storage poll/allocation/collection and SDK ticks controlled. 24 native message codecs plus explicit bulk-writer boundary codec cases; full memory, normalized large stack scratch, callback order/snapshots, full queue/drain, cancellation, allocator retries, captured wrapper/object replacement, signed sequences, encoder-changed alignment, fragment boundaries and wrapping counters. Reliable observer dispatch runs through actual enqueue with signed connection states, missing connections and 64-bit mask boundary types, using explicit synthetic descriptors for out-of-catalog message indices. Enqueue-then-clear sequences execute recovered cleanup, check each fragment release and zero reference/byte accounting. No provider implementation or full network/session lifecycle.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
