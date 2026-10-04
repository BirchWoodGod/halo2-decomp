#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STACK,STOP
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops as Send
from message_dispatch_oracle import NativeCodec,Platform
from network_storage_queue_oracle import QueueOps,Poll,Allocate,Collect
class Context(C.Structure):
    _fields_=[('clock',C.POINTER(Operations)),('send',C.POINTER(Send)),('codec',C.POINTER(Platform)),('queue',C.POINTER(QueueOps)),('message8',C.c_uint32),('storage_scratch',C.c_uint32),('packet',C.c_uint32),('workspace28',C.POINTER(C.c_uint8))]
def suite(h):
    # The reliable enqueue path uses a frame larger than the default stack map.
    h.u.mem_map(STACK-0x10000,0x10000)
    rng=random.Random(0x88360);s=h.table;writer=s+0x3000;table=s+0x4000;conn=s+0x5000;endpoint=s+0x5200;obj=s+0x5600;vt=s+0x5680;wrapper=s+0x5700;allocation=s+0x5800;message=s+0x6000;scratch=s+0x8000
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    original=[];native=[];frames={};coverage={'ticks':0,'poll':0,'allocate':0,'collect':0,'writer':0,'storage':0}
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,args):
        events.append((kind,args,bytes(read(conn,0xf8)),bytes(read(s,0x2850))))
        if events is original:coverage[kind]+=1
        if kind=='ticks':
            if case%3==0:write(conn+0x48,bytes([0x10 if case%2 else 0]));write(conn+0x54,pack(99))
            return (0xfffffff0+len(events))&0xffffffff
        if kind=='poll':return 255 if case%5==0 else 0
        if kind=='allocate':return allocation
        return 0
    ticks=Ticks(lambda ctx:event(h.read,nw,native,'ticks',()));clock=Operations(None,ticks,Provider());send=Send()
    poll=Poll(lambda ctx,f,o,v:event(h.read,nw,native,'poll',(f,o,v)))
    alloc=Allocate(lambda ctx,f,o,n,a,b:event(h.read,nw,native,'allocate',(f,o,n,a,b)))
    collect=Collect(lambda ctx,f,o,v:event(h.read,nw,native,'collect',(f,o,v)));queue=QueueOps(None,poll,alloc,collect)
    codec=Platform();native_codec=NativeCodec(h.memory,C.pointer(clock),s+0x6100)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(native_codec))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    workspace=(C.c_uint8*28)();ctx=Context(C.pointer(clock),C.pointer(send),C.pointer(codec),C.pointer(queue),message,scratch,s+0x6200,workspace)
    def hook(u,at,size,arg):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x89180:frames['message']=esp-8;return
        if at==0x7b140:coverage['writer']+=1;return
        if at==0x95580:
            coverage['storage']+=1;frames['storage']=((esp-4)&~7)-0x10054-12+0x24;u.mem_write(frames['storage'],seed);return
        if at==0x3314b0:kind='ticks';args=();purge=0
        elif at==STOP+0x800:kind='poll';args=(at,u.reg_read(X.UC_X86_REG_ECX),u32(u.mem_read,esp+4));purge=4
        elif at==STOP+0x900:kind='allocate';args=(at,u.reg_read(X.UC_X86_REG_ECX),*struct.unpack('<III',u.mem_read(esp+4,12)));purge=12
        else:kind='collect';args=(at,u.reg_read(X.UC_X86_REG_ECX),u32(u.mem_read,esp+4));purge=4
        value=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,esp));u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for at in [0x89180,0x7b140,0x95580,0x3314b0,STOP+0x800,STOP+0x900,STOP+0xa00]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    for name,address,register_name in [('accept',0x88360,'esi'),('send_accept',0x89180,'eax')]:
        fn=getattr(h.lib,'h2_network_connection_'+name);fn.argtypes=[C.POINTER(Memory),C.POINTER(Context),C.c_uint32,C.c_uint32];fn.restype=None
        for case in range(384):
            frames.clear();original.clear();native.clear();h.write(s,bytes(0x3000));h.write(conn,rng.randbytes(0xf8));h.write(writer,bytes(0x700));h.write(endpoint,bytes(0x224))
            h.write(writer+8,pack(endpoint)+pack(table));h.write(endpoint+0x20,pack(1));h.write(conn+4,pack(writer));h.write(conn+0x14,pack(0));h.write(conn+0x82,struct.pack('<H',4));h.write(conn+0x48,bytes([0x10 if case%2 else 0]));h.write(conn+0x54,pack([0,2,3,3,4,5][case%6]))
            h.write(0x4d87dc,pack(s));h.write(0x510548,bytes([1 if case%4==0 else 0]));h.write(0x51054c,pack(100));h.write(0x510550,pack(0));h.write(0x55e755,b'\0')
            h.write(s,pack(vt));h.write(vt+4,pack(STOP+0x800));h.write(s+12,pack(table));h.write(s+20,pack(8));h.write(s+0x2848,pack(case%3));h.write(obj,pack(vt+0x40));h.write(vt+0x54,pack(STOP+0x900));h.write(vt+0x68,pack(STOP+0xa00));h.write(wrapper,pack(obj)+pack(0));h.write(0x4d87f8,pack(wrapper))
            seed=rng.randbytes(0x10037);h.write(scratch,seed);incoming=rng.randbytes(8);h.write(message,incoming);value=rng.getrandbits(32) if name=='accept' else case%3
            def run():
                fn(h.memory,C.byref(ctx),conn,value)
                assert h.read(message,8)==bytes(h.u.mem_read(frames['message'],8)),(name,case,'message')
                if 'storage' in frames:
                    expected=bytearray(h.u.mem_read(frames['storage'],len(seed)));expected[:4]=pack(scratch+0x38)
                    assert h.read(scratch,len(seed))==expected,(name,case,'storage')
                nw(message,incoming);nw(scratch,seed)
            h.call(name,address,{register_name:conn},[value],run)
            assert original==native,(name,case)
    assert coverage['writer'] and coverage['storage'] and coverage['allocate'],coverage
    return coverage
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-accept-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_connection_accept.c','include/halo2/network_connection_accept.h','src/network_connection_setup.c','src/network_storage_queue.c','tests/network_connection_accept_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original accept transition, timers, response sender, writer/reliable queues and native codecs. Full memory, message and normalized reliable scratch, callback snapshots. SDK clock and provider allocation/poll controlled. Fresh writer avoids flush/live socket I/O.')
    (ROOT/args.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
