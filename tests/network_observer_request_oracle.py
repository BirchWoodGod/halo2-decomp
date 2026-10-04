#!/usr/bin/env python3
"""Incoming request composition against original x86; only SDK/events controlled."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STACK,STOP
from data_array_oracle import ROOT,Memory,EXPECTED
from network_connection_accept_oracle import Context as Accept
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops as Send
from network_connection_oracle import Callbacks,Closed
from network_observer_query_oracle import QueryOps,Query,Events,StateOne,Connection
from network_identity_resolve_oracle import Ops as Identity,Resolve
from network_resolution_oracle import Resolution,Status
from network_registration_oracle import Operations as Registration,Call
from message_dispatch_oracle import NativeCodec,Platform
from network_storage_queue_oracle import QueueOps,Poll,Allocate,Collect
from network_storage_oracle import Operations as StorageOps,Lookup,Release
class Context(C.Structure):
    _fields_=[('accept',C.POINTER(Accept)),('query',C.POINTER(QueryOps)),('identity',C.POINTER(Identity)),('resolution',C.POINTER(Resolution)),('callbacks',C.POINTER(Callbacks)),('registration',C.POINTER(Registration)),('events',C.POINTER(Events)),('storage',C.c_void_p)]+[(n,C.c_uint32) for n in ['local88','query4','prepare4','close16','storage8','open_message8']]
def suite(h):
    h.u.mem_map(STACK-0x10000,0x10000)
    # Terminate decoding before the mapped stub page boundary.
    h.u.mem_write(STOP+0xf00,b"\xc2\x08\x00")
    s=h.table;observer=s;writer=s+0x6000;table=s+0x6800;endpoint=s+0x7000;conn=s+0x7400;address=s+0x7800;request=s+0x7820;obj=s+0x7900;vt=s+0x7920;record=s+0x7940;local=s+0xa000;packet=s+0xb000
    storage=s+0x1e000;provider=s+0x20b00;provider_vt=s+0x20b40;wrapper=s+0x20b80;allocation=s+0x20c00;reliable_scratch=s+0xd000
    stream=s+0x21000
    rng=random.Random(0x785d0);frames={};original=[];native=[];coverage={}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,kind,args):
        shown=args[:1] if kind=='identity' else args[:3] if kind=='lookup' else args
        log.append((kind,shown,bytes(read(observer,0x4e00)),bytes(read(conn,0xf8))))
        if log is original:coverage[kind]=coverage.get(kind,0)+1
        if kind=='lookup':write(args[3],pack(0x12345678));return 255
        if kind=='poll':return 255 if case%5==0 else 0
        if kind=='allocate':return allocation
        if kind=='query':
            if case%19==0:write(request+4,pack(0))
            return 2 if case%8 else case%5
        if kind=='identity':
            write(args[1],identity_data);write(args[2],key_data+bytes(12));return 1 if case%11==0 else 0
        if kind=='closed' and case%3==0:write(conn+0x54,pack(5))
        if kind=='ticks':
            if case%9==0:write(request,pack(0x76543210));write(conn+0x50,pack(0x76543210))
            return (0xfffffff0+len(log))&0xffffffff
        return 0
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks',()));clock=Operations(None,tick,Provider());send=Send()
    qcb=Query(lambda ctx,ip:event(h.read,nw,native,'query',(ip,)));query=QueryOps(None,qcb)
    icb=Resolve(lambda ctx,ip,ident,key:event(h.read,nw,native,'identity',(ip,ident,key)));identity=Identity(None,icb,local+0x100)
    pcb=Status(lambda ctx,ip:event(h.read,nw,native,'prepare',(ip,)));resolution=Resolution(None,Resolution._fields_[1][1](),pcb)
    ccb=Closed(lambda ctx,fn,arg:event(h.read,nw,native,'closed',(fn,arg)));callbacks=Callbacks(None,ccb)
    rcb=Call(lambda ctx,ip:event(h.read,nw,native,'release',(ip,)));registration=Registration(None,rcb,Call())
    scb=StateOne(lambda ctx,fn,obj,index:event(h.read,nw,native,'state',(fn,obj,index)))
    ncb=Connection(lambda ctx,fn,obj,index,ident,connected:event(h.read,nw,native,'notify',(fn,obj,index,ident,connected)));events=Events(None,scb,ncb)
    codec=Platform();nc=NativeCodec(h.memory,C.pointer(clock),local+0x1c0)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(nc))
    poll=Poll(lambda ctx,fn,obj,v:event(h.read,nw,native,'poll',(fn,obj,v)))
    alloc=Allocate(lambda ctx,fn,obj,n,a,b:event(h.read,nw,native,'allocate',(fn,obj,n,a,b)))
    collect=Collect(lambda ctx,fn,obj,v:event(h.read,nw,native,'collect',(fn,obj,v)));queue=QueueOps(None,poll,alloc,collect)
    workspace=(C.c_uint8*28)();accept=Accept(C.pointer(clock),C.pointer(send),C.pointer(codec),C.pointer(queue),local+0x160,reliable_scratch,packet,workspace)
    lookup=Lookup(lambda ctx,fn,obj,handle,out:event(h.read,nw,native,'lookup',(fn,obj,handle,out)))
    release=Release(lambda ctx,fn,obj,handle,val:event(h.read,nw,native,'storage_release',(fn,obj,handle,val)));storage_ops=StorageOps(None,lookup,release)
    ctx=Context(C.pointer(accept),C.pointer(query),C.pointer(identity),C.pointer(resolution),C.pointer(callbacks),C.pointer(registration),C.pointer(events),C.cast(C.pointer(storage_ops),C.c_void_p),local,local+0x140,local+0x144,local+0x148,local+0x168,local+0x170)
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,arg):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x785d0:frames['main']=esp-0x88;u.mem_write(esp-0x88,seed[:0x88]);return
        if at in [0x88220,0x88360,0x88650,0x7b140]:
            label={0x88220:'open',0x88360:'accept',0x88650:'close',0x7b140:'writer'}[at];coverage[label]=coverage.get(label,0)+1
            if at==0x88650:u.mem_write(esp-12,seed[0x148:0x154])
            return
        if at==0x94bf0:
            frames['clear']=esp-8;u.mem_write(esp-8,seed[0x168:0x170]);coverage['clear']=coverage.get('clear',0)+1;return
        if at==0x94ddd:frames['clear_result']=bytes(u.mem_read(frames['clear'],8));return
        if at==0x95cf0:coverage['stream_reset']=coverage.get('stream_reset',0)+1;return
        if at==0x891bd:
            frames['reliable_result']=bytes(u.mem_read(frames['reliable'],len(reliable_seed)));return
        if at==0x95580:
            coverage['reliable']=coverage.get('reliable',0)+1;frames['reliable']=((esp-4)&~7)-0x10054-12+0x24;u.mem_write(frames['reliable'],reliable_seed);return
        if at==0x7ab60:u.mem_write(esp-32,seed[0x100:0x120]);return
        if at==0x3cd35a:kind='query';args=(u32(u.mem_read,esp+4),);purge=4
        elif at==0x3cd32d:kind='identity';args=struct.unpack('<III',u.mem_read(esp+4,12));purge=12
        elif at==0x3cd34f:kind='prepare';args=(u32(u.mem_read,esp+4),);purge=4
        elif at==0x3cd344:kind='release';args=(u32(u.mem_read,esp+4),);purge=4
        elif at==0x3314b0:kind='ticks';args=();purge=0
        elif at in [STOP+0xe00,STOP+0xf00]:
            kind='lookup' if at==STOP+0xe00 else 'storage_release';args=(at,u.reg_read(X.UC_X86_REG_ECX),*struct.unpack('<II',u.mem_read(esp+4,8)));purge=8
        elif at==STOP+0xb00:kind='poll';args=(at,u.reg_read(X.UC_X86_REG_ECX),u32(u.mem_read,esp+4));purge=4
        elif at==STOP+0xc00:kind='allocate';args=(at,u.reg_read(X.UC_X86_REG_ECX),*struct.unpack('<III',u.mem_read(esp+4,12)));purge=12
        elif at==STOP+0xd00:kind='collect';args=(at,u.reg_read(X.UC_X86_REG_ECX),u32(u.mem_read,esp+4));purge=4
        elif at==STOP+0x800:kind='closed';args=(at,u32(u.mem_read,esp+4));purge=4
        else:
            kind='state' if at==STOP+0x900 else 'notify';purge=4 if kind=='state' else 12
            args=(at,u.reg_read(X.UC_X86_REG_ECX),*struct.unpack('<'+'I'*(purge//4),u.mem_read(esp+4,purge)))
        result=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,esp));u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for at in [0x94bf0,0x94ddd,0x95cf0,STOP+0xe00,STOP+0xf00,0x891bd,0x95580,STOP+0xb00,STOP+0xc00,STOP+0xd00,0x785d0,0x88220,0x88360,0x88650,0x7b140,0x7ab60,0x3cd35a,0x3cd32d,0x3cd34f,0x3cd344,0x3314b0,STOP+0x800,STOP+0x900,STOP+0xa00]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_handle_request;fn.argtypes=[C.POINTER(Memory),C.POINTER(Context)]+[C.c_uint32]*3;fn.restype=None
    for case in range(2048):
        frames.clear();original.clear();native.clear();h.write(observer,bytes(0x5000));h.write(writer,bytes(0x700));h.write(endpoint,bytes(0x224));h.write(conn,bytes(0xf8));h.write(0x4cf7d4,bytes(256))
        h.write(observer+8,pack(writer));h.write(writer+8,pack(endpoint)+pack(table));h.write(conn,pack(endpoint)+pack(writer));h.write(conn+0x10,pack(0xffffffff)*2);h.write(conn+0x3c,pack(record));h.write(record+4,pack(conn)+pack(STOP+0x800));h.write(conn+0x44,pack(0));h.write(conn+0x4c,pack(19));h.write(conn+0x50,pack(29));h.write(conn+0x54,pack([0,1,2,3,4,5,0xffffffff,0x80000000][case//16%8]));h.write(0x4d87d4,pack(conn))
        addr=pack(0x7f000001 if case%17==0 else 0x00123456)+bytes(12)+struct.pack('<HH',1000,4);h.write(address,addr);h.write(conn+0x70,addr)
        if case%7==0:h.write(conn+0x70,pack(0x0056789a))
        flags=(case%256 if case<256 else 0)|(0xffffff00 if case%3==0 else 0);h.write(request,pack(30 if case%5==0 else 29)+pack(flags))
        identity_data=rng.randbytes(36);key_data=rng.randbytes(8);index=case%15;entry=observer+0xa8+index*0x528
        if case%13:
            h.write(entry,pack([4,6,7][case//4%3]));h.write(entry+9,b'\1');h.write(entry+0x14,identity_data);h.write(entry+0x5c,addr)
            if case%23==0:h.write(entry+0x14+(case%9)*4,pack(0))
            if case%29==0:h.write(entry+9,b'\0')
            if index>0:
                earlier=observer+0xa8+(index-1)*0x528
                h.write(earlier,pack(4));h.write(earlier+0x14,identity_data)
        h.write(obj,pack(vt));h.write(vt+12,pack(STOP+0xa00)+pack(STOP+0x900));h.write(observer+0x14,pack(obj));h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack(100));h.write(0x510550,pack(0));h.write(0x55e755,b'\0')
        h.write(storage,bytes(0x2850));h.write(storage,pack(provider_vt));h.write(provider_vt+4,pack(STOP+0xb00));h.write(storage+12,pack(table));h.write(storage+20,pack(8));h.write(storage+0x2848,pack(case%3))
        h.write(provider,pack(provider_vt+0x10));h.write(provider_vt+0x24,pack(STOP+0xc00));h.write(provider_vt+0x38,pack(STOP+0xd00));h.write(wrapper,pack(provider)+pack(0));h.write(0x4d87f8,pack(wrapper));h.write(0x4d87dc,pack(storage))
        if case>=1536:
            h.write(conn+0x48,pack(0x10));h.write(conn+0x54,pack(3));h.write(conn+0x14,pack(0));h.write(conn+0x70,addr);h.write(request,pack(29))
        h.write(stream,rng.randbytes(0x97c));h.write(0x4d87d8,pack(stream))
        if case>=1792:
            h.write(conn+0x54,pack(2));h.write(conn+0x10,pack(0));h.write(storage+4,b'\1');h.write(storage+0x18,pack(1));h.write(storage+0x28,pack(1));h.write(storage+0x2d,b'\3');h.write(storage+0x30,pack(17));h.write(storage+0x2848,pack(3));h.write(wrapper+4,pack(1))
            h.write(provider_vt+0x10,pack(STOP+0xf00)+pack(STOP+0xe00))
        reliable_seed=rng.randbytes(0x10037);h.write(reliable_scratch,reliable_seed)
        seed=rng.randbytes(0x200);h.write(local,seed)
        def run():
            fn(h.memory,C.byref(ctx),observer,address,request)
            assert h.read(local,0x88)==bytes(h.u.mem_read(frames['main'],0x88)),(case,'locals')
            if 'clear_result' in frames:assert h.read(local+0x168,8)==frames['clear_result'],(case,'clear scratch')
            if 'reliable' in frames:
                expected=bytearray(frames['reliable_result']);expected[:4]=pack(reliable_scratch+0x38)
                actual=h.read(reliable_scratch,len(reliable_seed))
                assert actual==expected,(case,'reliable scratch',[(i,actual[i:i+8].hex(),expected[i:i+8].hex()) for i in range(len(actual)) if actual[i]!=expected[i]][:8])
            nw(reliable_scratch,reliable_seed);nw(local,seed)
        try:h.call('handle_request',0x785d0,{},[observer,address,request],run)
        except U.UcError:
            print('oracle failure',case,hex(h.u.reg_read(X.UC_X86_REG_EIP)),[(e[0],e[1]) for e in original]);raise
        assert original==native,(case,'callbacks')
    assert all(coverage.get(k) for k in ['query','identity','writer','open','accept','close','notify','reliable','allocate','clear','lookup','storage_release','stream_reset']),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-request-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_request.c','include/halo2/network_observer_request.h','tests/network_observer_request_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original request handler with actual recovered engine callees. Full memory, main local frame and SDK/event snapshots. Ordinary writer and reliable queues with actual codecs, normalized reliable scratch. Includes reopening with stream reset and queued storage cleanup. Live socket flush remains outside this suite.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
