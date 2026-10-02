#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from random_oracle import Sources,Source
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops
from message_dispatch_oracle import NativeCodec,Platform as Codecs
Fill=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32)
class Platform(C.Structure):
    _fields_=[('context',C.c_void_p),('fill',Fill)]

def suite(h):
    rng=random.Random(0x7ad50);output=h.table;cache=output+0x1000;empty=output+0x4000;alternate=empty+0x100
    original=[];native=[];iteration=0;stage='';target=output
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,data):C.memmove(h.pointer+p-BASE,data,len(data))
    def scalar(kind,attempt):return (0x10203040*(kind+1)+iteration*0x19660d+attempt*0x3c6ef35f)&0xffffffff
    def fallback(attempt):
        seed=scalar(0,attempt)^scalar(1,attempt)^scalar(2,attempt);data=[]
        for i in range(8):seed=(seed*0x19660d+0x3c6ef35f)&0xffffffff;data.append(seed>>24)
        return bytes(data)
    def event(read,write,events,kind,args):
        attempt=sum(e[0]==kind for e in events)
        events.append((kind,args,bytes(read(target,128)),bytes(read(0x4d8eb0,28)),bytes(read(cache,0x784*4)),bytes(read(0x4cf790,1)),bytes(read(0x46725c,4))))
        if iteration%7==0:
            write(0x46725c,pack(alternate)) # comparison must fetch pointer after callbacks
        if stage=='start' and iteration%3==0:
            write(0x4d8eb4,bytes([0 if iteration%2 else 255]));write(0x4d8eb5,b'\xaa')
            write(0x4d8ec4,pack(0x1234));write(0x4d8ec8,pack(alternate))
        if iteration%5==0:write(0x4cf790,b'\0' if kind==3 else b'\xff')
        if kind==3:
            dest,count=args
            if count<=128:
                sentinel=struct.unpack('<I',read(0x46725c,4))[0]
                value=bytes(read(sentinel,8)) if stage!='bytes' and attempt<iteration%3 else bytes((i*17+iteration+attempt+1)&255 for i in range(count))
                write(dest,value[:count])
            return 0xdeadbeef
        return scalar(kind,attempt)
    callbacks=[Source(lambda ctx,k=k:event(h.read,nw,native,k,())) for k in range(3)]
    sources=Sources(None,*callbacks);fill=Fill(lambda ctx,p,n:event(h.read,nw,native,3,(p,n)));platform=Platform(None,fill)
    addresses=[0x321aae,0x321f75,0x3314b0,0x3cd0c0]
    def hook(u,at,size,ctx):
        kind=addresses.index(at);esp=u.reg_read(X.UC_X86_REG_ESP)
        if kind==0:assert struct.unpack('<I',u.mem_read(esp+4,4))[0]==0
        args=struct.unpack('<II',u.mem_read(esp+4,8)) if kind==3 else ()
        value=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+(8 if kind==3 else 0))
    for at in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    prefix=[C.POINTER(Memory),C.POINTER(Sources),C.POINTER(Platform)]
    bytefn=h.lib.h2_random_bytes;bytefn.argtypes=prefix+[C.c_uint32]*2;bytefn.restype=None
    idfn=h.lib.h2_random_identity;idfn.argtypes=prefix+[C.c_uint32];idfn.restype=None
    start=h.lib.h2_discovery_start;start.argtypes=prefix+[C.c_uint32]*2;start.restype=C.c_uint8
    for stage in ['bytes','identity','start']:
        for iteration in range(256):
            original.clear();native.clear();target=0x4d8ebc if stage=='start' else output
            h.write(output,rng.randbytes(256));h.write(cache,rng.randbytes(0x784*4));h.write(empty,rng.randbytes(0x200))
            h.write(0x4d8eb0,rng.randbytes(128));h.write(0x4d8b18,bytes([0 if iteration%13==0 else 255,0 if iteration%17==0 else 1]))
            h.write(0x4d8eb4,bytes([255 if iteration%11==0 else 0]));h.write(0x4cf790,bytes([iteration%2]))
            h.write(0x46725c,pack(empty));h.write(empty,fallback(0));h.write(alternate,fallback(0))
            if stage=='bytes':
                count=[0,1,2,7,8,31,64,127,128,0x80000000,0xffffffff][iteration%11]
                h.call('random_bytes',0x7ad80,dict(edi=count),[target],lambda:bytefn(h.memory,C.byref(sources),C.byref(platform),target,count))
            elif stage=='identity':
                h.call('random_identity',0x7ad50,dict(ebx=target),[],lambda:idfn(h.memory,C.byref(sources),C.byref(platform),target))
                assert h.read(target,8)!=h.read(h.u32(0x46725c),8)
            else:
                count=[0,1,2,4,0x40000000,0x40000001,0x80000001,0xc0000002][iteration%8]
                h.call('discovery_start',0xb2e30,dict(eax=cache,esi=count),[],lambda:start(h.memory,C.byref(sources),C.byref(platform),cache,count),255)
            assert original==native,(stage,iteration)

    # Carry the same state through startup, query encoding, a matching reply,
    # then expiry. Every original engine callee executes unchanged.
    stage='integrated';target=0x4d8ebc
    writer=output+0x8000;table=output+0x9000;local=output+0x9800;packet=output+0xa000;reply=output+0xc000
    clock=Operations(None,Ticks(),Provider());send=Ops()
    codec_context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Codecs()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Codecs),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(codec_context))
    register=h.lib.h2_messages_register_discovery;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    update=h.lib.h2_discovery_update;update.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Codecs),C.c_uint32,C.c_uint32,C.POINTER(C.c_uint8)];update.restype=None
    handle=h.lib.h2_message_handle_broadcast_reply;handle.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];handle.restype=None
    incoming=bytes(32)
    def seed_local(u,at,size,ctx):u.mem_write(u.reg_read(X.UC_X86_REG_ESP)-32,incoming)
    h.u.hook_add(U.UC_HOOK_CODE,seed_local,begin=0xb2ea0,end=0xb2ea0)
    def native_update():
        update(h.memory,C.byref(clock),C.byref(send),C.byref(codec),local,packet,(C.c_uint8*28)())
        assert h.read(local,32)==bytes(h.u.mem_read(0x2008000-32,32))
        nw(local,incoming)
    for iteration in range(16):
        original.clear();native.clear()
        h.write(0x4d8eb0,pack(writer)+bytes(24));h.write(0x4d8b18,b'\x01\x01');h.write(0x4cf790,bytes([iteration%2]))
        h.write(0x46725c,pack(empty));h.write(empty,fallback(0));h.write(alternate,fallback(0))
        h.write(writer,bytes(0x700));h.write(writer+12,pack(table));h.write(cache,rng.randbytes(0x784*4))
        h.call('integrated_discovery_start',0xb2e30,dict(eax=cache,esi=4),[],lambda:start(h.memory,C.byref(sources),C.byref(platform),cache,4),255)
        assert original==native and h.read(cache,0x784*4)==bytes(0x784*4)
        h.write(0x510548,b'\x01');h.write(0x51054c,pack(1501));incoming=rng.randbytes(32);h.write(local,incoming)
        h.call('integrated_discovery_query',0xb2ea0,{},[],native_update)
        assert h.u32(0x4d8eb8)==1501 and h.read(writer+0x14,1)==b'\x01'
        h.write(reply,b'\x02\x00\x00\x00'+h.read(0x4d8ebc,8)+rng.randbytes(0x714))
        h.call('integrated_discovery_reply',0x940b0,dict(eax=reply),[local+12],lambda:handle(h.memory,C.byref(clock),reply,local+12))
        assert h.read(cache,1)==b'\x01' and h.u32(cache+4)==1501
        h.write(0x51054c,pack(3502));h.write(0x4d8eb5,b'\x00');incoming=rng.randbytes(32);h.write(local,incoming)
        h.call('integrated_discovery_expire',0xb2ea0,{},[],native_update)
        assert h.read(cache,0x784*4)==bytes(0x784*4) and h.read(0x4d8eb5,1)==b'\x01'

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/discovery-start-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/random.c','include/halo2/random.h','src/discovery.c','include/halo2/discovery.h','tests/discovery_start_oracle.py','tests/random_oracle.py','tests/hash_crc_oracle.py','tests/message_dispatch_oracle.py','tests/network_state_oracle.py','tests/network_send_oracle.py','src/message_dispatch.c','src/network_messages.c']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original random bytes, non-sentinel identity generation and discovery start with engine callees intact. Only CRT/SDK entropy controlled. Full memory, boundary snapshots, entropy ordering, zero/negative byte counts, sentinel retries and pointer changes, active/transport gates, raw AL, callback state mutations and wrapped cache-zero sizes. Sixteen start/query/reply/expiry sequences retain actual engine callees and native codec dispatch. No native Linux entropy backend or live discovery/game boot.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
