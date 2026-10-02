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

def suite(h):
    rng=random.Random(0xb2ea0);writer=h.table;table=writer+0x1000;cache=writer+0x2000;other=writer+0x4000;local=writer+0x6000;packet=writer+0x7000
    original=[];native=[];iteration=0;now=0;incoming=b''
    def nw(p,data):C.memmove(h.pointer+p-BASE,data,len(data))
    def tick(read,write,events):
        events.append((bytes(read(0x4d8eb0,28)),bytes(read(cache,0x784*4)),bytes(read(other,0x784*4)),bytes(read(writer,0x700))))
        n=len(events)
        if iteration%7==0:
            if n==1:write(0x4d8eb8,struct.pack('<I',now)) # captured previous timestamp must survive
            if n==2:
                write(0x4d8ec8,struct.pack('<I',other));write(0x4d8ec4,struct.pack('<I',3))
                write(cache+4,struct.pack('<I',now))
            if n==3:write(0x4d8ec4,bytes(4))
        if iteration%11==0 and n==1:
            write(0x510548,b'\x01');write(0x51054c,struct.pack('<I',(now+19)&0xffffffff))
        return now
    cb=Ticks(lambda ctx:tick(h.read,nw,native));clock=Operations(None,cb,Provider());send=Ops()
    context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    fn=h.lib.h2_discovery_update;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.c_uint32,C.c_uint32,C.POINTER(C.c_uint8)];fn.restype=None
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0xb2ea0:u.mem_write(esp-32,incoming);return
        value=tick(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    for at in [0xb2ea0,0x3314b0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    register=h.lib.h2_messages_register_discovery;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    # Generate table using recovered registration, then give identical bytes to x86.
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    for iteration in range(512):
        original.clear();native.clear();incoming=rng.randbytes(32)
        h.write(local,incoming);h.write(writer,bytes(0x700));h.write(writer+12,struct.pack('<I',table))
        now=[0,1,1500,2000,0x7fffffff,0x80000000,0xfffffffe,0xffffffff][iteration%8]
        elapsed=[0,1499,1500,1501,2000,2001,0x7fffffff,0x80000000][iteration//8%8]
        h.write(0x4d8eb0,struct.pack('<I',writer)+bytes([0 if iteration%19==0 else 255,iteration%2,0,0])+struct.pack('<I',(now-elapsed)&0xffffffff)+rng.randbytes(8)+struct.pack('<II',[4,4,4,0,0xffffffff][iteration%5],cache))
        h.write(0x510548,bytes([iteration//64%2]));h.write(0x51054c,struct.pack('<I',now))
        for base in [cache,other]:
            h.write(base,rng.randbytes(0x784*4))
            for i in range(4):
                age=[1999,2000,2001,0x80000000,0xffffffff,0,0x7fffffff][(iteration+i)%7]
                h.write(base+i*0x784,bytes([0 if (iteration+i)%9==0 else 255]));h.write(base+i*0x784+4,struct.pack('<I',(now-age)&0xffffffff))
        def run():
            fn(h.memory,C.byref(clock),C.byref(send),C.byref(codec),local,packet,(C.c_uint8*28)())
            assert h.read(local,32)==bytes(h.u.mem_read(0x2008000-32,32)),iteration
            nw(local,incoming)
        h.call('discovery_update',0xb2ea0,{},[],run)
        assert original==native,iteration

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/discovery-update-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/discovery.c','include/halo2/discovery.h','src/network_messages.c','src/message_dispatch.c','tests/discovery_update_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py','tests/message_dispatch_oracle.py','tests/network_send_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original discovery update, enqueue, broadcast search encoder and bitstream callees intact. Only SDK time controlled. Fresh writer cases; no flush/send in this suite. Signed timer boundaries, wraparound, inactive entries, signed cache count, captured timestamps, changing cache base/count, clock override changes, dirty flags, full persistent memory and original local scratch. No live network or game boot.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
