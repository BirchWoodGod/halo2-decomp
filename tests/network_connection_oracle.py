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
Closed=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32)
class Callbacks(C.Structure):
    _fields_=[('context',C.c_void_p),('closed',Closed)]

def suite(h):
    rng=random.Random(0x88650);writer=h.table;table=writer+0x1000;endpoint=writer+0x2000;other=writer+0x2600;connections=writer+0x3000;records=writer+0x4000;local=writer+0x4800;packet=writer+0x5000;alternate=writer+0x7000;stub=0x3000800
    original=[];native=[];iteration=0;drain=False;frame={};incoming=bytes(12)
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,function,argument):
        events.append((function,argument,bytes(read(writer,0x700)),bytes(read(endpoint,0x1800)),bytes(read(alternate,0x400))))
        if iteration%3==0:
            write(argument,pack(other));write(argument+0x44,pack(2));write(argument+0x70,bytes(range(20)))
        if drain and iteration%7==0:
            write(0x4d87d4,pack(alternate));write(endpoint+0x20,pack(2))
        write(argument+0x54,pack(99)) # final close state must overwrite this
    cb=Closed(lambda ctx,function,argument:event(h.read,nw,native,function,argument));callbacks=Callbacks(None,cb)
    clock=Operations(None,Ticks(),Provider());send=Ops();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x88650:
            frame['local']=esp-12;u.mem_write(esp-12,incoming);return
        argument=struct.unpack('<I',u.mem_read(esp+4,4))[0];event(u.mem_read,u.mem_write,original,at,argument)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for at in [stub,0x88650]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    prefix=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks)]
    close=h.lib.h2_network_connection_close;close.argtypes=prefix+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];close.restype=None
    closeall=h.lib.h2_network_endpoint_close_connections;closeall.argtypes=prefix+[C.c_uint32]*3+[C.POINTER(C.c_uint8)];closeall.restype=None
    for drain in [False,True]:
        for iteration in range(384):
            original.clear();native.clear();frame.clear();incoming=rng.randbytes(12);h.write(local,incoming)
            h.write(writer,bytes(0x700));h.write(writer+8,struct.pack('<II',endpoint,table))
            for ep in [endpoint,other]:
                h.write(ep,rng.randbytes(0x588));h.write(ep+0x20,pack([0,1,2,4,0xffffffff][iteration%5]))
                for i in range(4):h.write(ep+0x24+i*32,pack(i))
            h.write(0x4d87d4,pack(connections))
            for bank,base in enumerate([connections,alternate]):
                h.write(base,rng.randbytes(0x400))
                for i in range(4):
                    conn=base+i*0xf8;record=records+(bank*4+i)*16
                    h.write(conn,struct.pack('<II',endpoint,writer));h.write(conn+0x44,pack(i))
                    h.write(conn+0x3c,pack(record if (iteration+i)%4 else 0))
                    h.write(record+4,struct.pack('<II',conn,stub))
                    state=[0,2,3,5,5,0xffffffff][iteration%6] if not drain else [2,3,0xffffffff][(iteration+i)%3]
                    h.write(conn+0x54,pack(state));h.write(conn+0x70,rng.randbytes(20));h.write(conn+0x82,struct.pack('<H',4))
            reason=[0,1,3,6,17,31,0xffffffff][iteration//6%7]
            def run():
                args=(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks))
                if drain:closeall(*args,endpoint,local,packet,(C.c_uint8*28)())
                else:close(*args,connections,reason,local,packet,(C.c_uint8*28)())
                if 'local' in frame:assert h.read(local,12)==bytes(h.u.mem_read(frame['local'],12)),(drain,iteration)
                nw(local,incoming)
            if drain:h.call('endpoint_close_connections',0x92f10,{},[endpoint],run)
            else:h.call('connection_close',0x88650,dict(esi=connections,edi=reason),[],run)
            assert original==native,(drain,iteration)
            if drain:assert h.u32(endpoint+0x20)==0
            else:assert h.u32(connections+0x54)==2 and h.u32(connections+0x58)==reason

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_connection.c','include/halo2/network_connection.h','src/network_routing.c','src/network_messages.c','src/message_dispatch.c','tests/network_connection_oracle.py','tests/message_dispatch_oracle.py','tests/network_state_oracle.py','tests/network_send_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original connection close and endpoint-wide close, route removal, queue/closed-message codec and bitstream callees intact. Connection callback controlled. Fresh writer cases cover conditional message encoding; endpoint-wide fixtures avoid sends. Full memory, local message scratch, callback snapshots/mutations, route swaps and changing connection-table base/count. No flush/send in this suite; those have separate coverage. No complete network shutdown or game boot.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
