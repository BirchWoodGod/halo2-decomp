#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations as Clock,Ticks,Provider
from network_send_oracle import Ops as SendOps
from network_connection_oracle import Callbacks
from network_registration_oracle import Operations as Registration,Call
from network_observer_query_oracle import Query,QueryOps
from network_resolution_oracle import Resolve,Status,Resolution
from message_dispatch_oracle import Platform,NativeCodec
from network_observer_query_oracle import Events,StateOne,Connection
Request=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class Context(C.Structure):
    _fields_=[(n,C.c_void_p) for n in ["clock","send","codec","connections","registration","events","storage","query","resolution","context"]]+[("request",Request)]+[(n,C.c_uint32) for n in ["query4","detach16","resolution28","message8","storage8","packet"]]+[("workspace28",C.POINTER(C.c_uint8))]

def suite(h):
    rng=random.Random(0x78330);observer=h.table;writer=observer+0x3000;conn=observer+0x4000;local=observer+0x5000;querylocal=local+32;resolve_local=local+64;packet=observer+0x6000;config=observer+0x8000;objects=config+0x100;vtable=config+0x180;request_at=0x3000800;state_at=0x3000900;connection_at=0x3000a00;endpoint=observer+0x9000;table=observer+0xa000;stream=observer+0xb000;storage=observer+0xc000;connconfig=config+0x200
    session=h.lib.h2_heap_allocate(h.heap,0x7900);assert session
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    original=[];native=[];frames={};coverage={};iteration=0;entry=0
    def event(read,write,events,kind,*args):
        observed=args[:2]+(bytes(read(args[2],4)),) if kind=='resolve' else args
        events.append((kind,observed,bytes(read(observer,0x1800)),bytes(read(0x4cf7d4,0x100))))
        if events is original:coverage[kind]=coverage.get(kind,0)+1
        if iteration%7==0:
            write(session+0x54,pack(1));write(session+0x741c,pack(3));write(session+0x7c+0x10c,b'\0')
        if kind=='ticks':
            n=sum(e[0]=='ticks' for e in events)
            if iteration%5==0:write(connconfig,pack(17+n));write(entry+8,bytes([read(entry+8,1)[0]^1]))
            if iteration%13==0:write(0x510548,b'\1');write(0x51054c,pack(101))
            return 100+n
        if kind in ['state','connection']:return 0
        if kind=='request':
            if iteration%7==0:write(entry+9,bytes([read(entry+9,1)[0]^8]));write(config,pack(0))
            return iteration%3
        if kind=='query':return [0,1,2,3,4,0xffffffff][iteration//16%6]
        if kind=='release':return 0
        if kind=='resolve':
            key=(args[1]-0x4cf7dc)//32
            if iteration%7==0:
                write(entry+9,bytes([read(entry+9,1)[0]|8]));write(entry+0x38,pack(u32(read,entry+0x38)&~8))
            if iteration%5==0:write(observer+key*36+0x20,pack(0xabcdef01))
            write(args[2],pack(0x01020300))
            return 0 if key==iteration//96%5 else 1
        return 0 if iteration%11 else 1
    query=Query(lambda ctx,ip:event(h.read,nw,native,'query',ip));query_ops=QueryOps(None,query)
    resolve=Resolve(lambda ctx,p,k,o:event(h.read,nw,native,'resolve',p,k,o));ready=Status(lambda ctx,ip:event(h.read,nw,native,'ready',ip));resolution=Resolution(None,resolve,ready)
    release=Call(lambda ctx,ip:event(h.read,nw,native,'release',ip));registration=Registration(None,release,Call())
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks'));clock=Clock(None,tick,Provider());send=SendOps();codec=Platform();callbacks=Callbacks()
    codec_context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(codec_context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    state_cb=StateOne(lambda ctx,f,o,i:event(h.read,nw,native,'state',f,o,i))
    connection_cb=Connection(lambda ctx,f,o,i,v,c:event(h.read,nw,native,'connection',f,o,i,v,c));events=Events(None,state_cb,connection_cb)
    request=Request(lambda ctx,f,o,i,r:event(h.read,nw,native,'request',f,o,i,r));workspace=(C.c_uint8*28)()
    ptr=lambda obj:C.cast(C.pointer(obj),C.c_void_p).value
    context=Context(ptr(clock),ptr(send),ptr(codec),ptr(callbacks),ptr(registration),ptr(events),None,ptr(query_ops),ptr(resolution),None,request,querylocal,local,resolve_local,local+112,local+128,packet,workspace)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x3314b0:
            value=event(u.mem_read,u.mem_write,original,'ticks');u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4);return
        if at in [0x88220,0x95cf0,0x94bf0,0x7b140]:
            label={0x88220:'open',0x95cf0:'stream',0x94bf0:'storage',0x7b140:'enqueue'}[at];coverage[label]=coverage.get(label,0)+1
            if at==0x88220:
                label='open_state:'+str(u32(u.mem_read,entry));coverage[label]=coverage.get(label,0)+1
            return
        if at==0x890b0:frames['message']=sp-8;u.mem_write(sp-8,message_seed);return
        if at in [0x890e8,0x89154,0x89172]:frames['message_bytes']=bytes(u.mem_read(frames['message'],8));return
        if at==0x88650:frames['close']=sp-12;u.mem_write(sp-12,frames.get('close_bytes',incoming[:12]));return
        if at==0x886d6:frames['close_bytes']=bytes(u.mem_read(frames['close'],12));return
        if at==0x776a0:
            frames['tick_calls']=frames.get('tick_calls',0)+1
            if frames['tick_calls']>1:coverage['recursive_tick']=coverage.get('recursive_tick',0)+1
            return
        if at in [request_at,state_at,connection_at]:
            kind={request_at:'request',state_at:'state',connection_at:'connection'}[at];purge={request_at:8,state_at:4,connection_at:12}[at]
            args=(at,u.reg_read(X.UC_X86_REG_ECX),*struct.unpack('<'+'I'*(purge//4),u.mem_read(sp+4,purge)))
            value=event(u.mem_read,u.mem_write,original,kind,*args)
            u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge);return
        if at==0x7acf0:frames['query']=sp-4;return
        if at in [0x7ad15,0x7ad19,0x7ad20,0x7ad27,0x7ad2e]:frames['query_bytes']=bytes(u.mem_read(frames['query'],4));return
        if at==0x784a0:frames['mark']=sp+4;frames['mark_bytes']=bytes(u.mem_read(sp+4,4));return
        if at==0x78551:frames['mark_bytes']=bytes(u.mem_read(sp+0x14,4));return
        if at==0x7adf0:frames['peer']=sp+4;return
        if at==0x7ae67:frames['peer_bytes']=bytes(u.mem_read(frames['peer'],4));return
        if at==0x7acc0:frames['ready']=sp-4;return
        if at==0x7ace4:frames['ready_bytes']=bytes(u.mem_read(frames['ready'],4));return
        if at==0x783d0:
            frames['lookup']=sp-20;u.mem_write(sp-20,frames.get('lookup_bytes',resolve_seed[:20]));return
        if at in [0x78472,0x7848d]:frames['lookup_bytes']=bytes(u.mem_read(frames['lookup'],20));return
        if at==0x3cd0ec:args=struct.unpack('<III',u.mem_read(sp+4,12));value=event(u.mem_read,u.mem_write,original,'resolve',*args);purge=12
        else:
            kind={0x3cd35a:'query',0x3cd344:'release',0x3cd34f:'ready'}[at];value=event(u.mem_read,u.mem_write,original,kind,u32(u.mem_read,sp+4));purge=4
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x3314b0,0x88220,0x95cf0,0x94bf0,0x7b140,0x890b0,0x890e8,0x89154,0x89172,0x88650,0x886d6,0x776a0,request_at,state_at,connection_at,0x7acf0,0x7ad15,0x7ad19,0x7ad20,0x7ad27,0x7ad2e,0x784a0,0x78551,0x7adf0,0x7ae67,0x7acc0,0x7ace4,0x783d0,0x78472,0x7848d,0x3cd0ec,0x3cd35a,0x3cd344,0x3cd34f]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_session_maintain_connections;fn.restype=None;fn.argtypes=[C.POINTER(Memory),C.POINTER(Context),C.c_uint32]
    selected=set()
    for case in range(4096):
        iteration=case%1024
        original.clear();native.clear();frames.clear();h.write(observer,rng.randbytes(0x1800));h.write(writer,bytes(0x700));h.write(observer+8,pack(writer));h.write(conn,bytes(0x400));h.write(0x4d87d4,pack(conn))
        for k in range(4):h.write(conn+k*0xf8+0x54,pack(2))
        index=iteration%4;entry=observer+0xa8+index*0x528
        h.write(entry+12,pack(index));h.write(entry+9,bytes([iteration%16]));h.write(entry+0x38,pack(iteration//480%16));h.write(entry+0x3c,pack(0xffffffff))
        h.write(entry+0x5c,pack(0x00123456)+bytes(12)+struct.pack('<HH',1000,4 if iteration%3 else 0))
        for k in range(4):
            slot=observer+k*36;h.write(slot+0x14,pack(objects+k*4));h.write(slot+0x18,pack(k if iteration%19 else 0xffffffff));h.write(slot+0x1c,pack(0 if iteration%23 else 1))
            h.write(0x4cf7d4+k*32,b'\1\0\0\0'+pack(0)+rng.randbytes(24))
        incoming=rng.randbytes(16);query_seed=rng.randbytes(4);resolve_seed=rng.randbytes(28);h.write(local,incoming);h.write(querylocal,query_seed);h.write(resolve_local,resolve_seed)
        current=[0,1,2,3,4,5,7,9][iteration//4%8]
        h.write(entry,pack(current));h.write(entry+4,pack(10));h.write(entry+8,bytes([iteration//32%8]));h.write(entry+10,struct.pack('<H',[0,1,2,0xffff][iteration//256%4]))
        h.write(observer+16,pack(config));h.write(config,bytes(0x80))
        for off in [0,0x24,0x48]:
            h.write(config+off,pack(2));h.write(config+off+4,pack(0 if current==2 or iteration%3 else 0x7fffffff));h.write(config+off+8,pack(0x7fffffff))
        h.write(config+0x6c,pack(0 if iteration%2 else 0x7fffffff));h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack(100))
        h.write(0x4cf568,pack(0x7fffffff));h.write(0x4cf56c,pack(0x7fffffff));h.write(entry+0x98,pack(99));h.write(entry+0x9c,pack(99))
        for k in range(4):h.write(objects+k*4,pack(vtable))
        h.write(vtable+8,pack(request_at)+pack(connection_at)+pack(state_at))
        if iteration%11==0:h.write(entry+12,pack(0xffffffff))
        h.write(endpoint,bytes(0x224));h.write(writer+8,pack(endpoint)+pack(table));h.write(connconfig,pack(10)+pack(3)+pack(0x7fffffff))
        h.write(stream,rng.randbytes(0x97c));h.write(storage,rng.randbytes(0x2850));h.write(storage+4,b'\0')
        h.write(0x4d87d8,pack(stream));h.write(0x4d87dc,pack(storage));h.write(0x4cf6e8,pack(1000));h.write(0x4cf70c,rng.randbytes(16))
        for k in range(4):
            c=conn+k*0xf8;h.write(c,pack(endpoint)+pack(writer));h.write(c+12,pack(connconfig));h.write(c+0x10,pack(0)+pack(0));h.write(c+0x44,pack(k))
        message_seed=rng.randbytes(8);storage_seed=rng.randbytes(8);h.write(local+112,message_seed);h.write(local+128,storage_seed)
        h.write(session,rng.randbytes(0x7900));h.write(session+8,pack(observer))
        state=5 if case<1024 else [0,1,2,3,4,5,6,7,8,9,10,0xffffffff,0x80000000][case%13]
        h.write(session+0x741c,pack(state));h.write(session+0x4c,pack(0xffffffff if case%17==0 else 1))
        h.write(session+0x7420,bytes([case%2]));h.write(session+0x54,pack([0,1,2,3,0xffffffff,0x80000000][case%6] if case>=1024 else 1))
        for peer in range(3):
            h.write(session+0x72dd+peer*20,bytes([1 if case<1024 else (case+peer)%3]))
            h.write(session+0x72e0+peer*20,pack(index));h.write(session+0x7c+peer*0x10c,bytes([(case+peer)%2]))
        def run():
            fn(h.memory,C.byref(context),session);value=0
            assert h.read(querylocal,4)==frames.get('query_bytes',query_seed),(iteration,'query')
            expected=frames.get('close_bytes',incoming[:12])+frames.get('mark_bytes',pack(0) if 'mark' in frames else incoming[12:])
            assert h.read(local,16)==expected,(iteration,'detach')
            expected=frames.get('lookup_bytes',resolve_seed[:20])+frames.get('peer_bytes',resolve_seed[20:24])+frames.get('ready_bytes',resolve_seed[24:])
            assert h.read(resolve_local,28)==expected,(iteration,'resolution')
            assert h.read(local+112,8)==frames.get('message_bytes',message_seed),(iteration,'message')
            assert h.read(local+128,8)==storage_seed
            nw(local+112,message_seed)
            if h.u32(entry+0x3c)<4:selected.add(h.u32(entry+0x3c))
            nw(querylocal,query_seed);nw(local,incoming);nw(resolve_local,resolve_seed);return value
        h.call('session_maintain_connections',0x62240,dict(edi=session),[],run,None)
        assert original==native,iteration
    assert coverage.get("request") and coverage.get("state") and coverage.get("recursive_tick"),coverage

    assert all(coverage.get(k) for k in ['open','open_state:5','enqueue','stream','storage','ticks']),coverage
    coverage['selected_consumers']=sorted(selected)
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-maintenance-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_session_maintenance.c','include/halo2/network_session_maintenance.h','src/network_session.c','tests/network_session_maintenance_oracle.py','src/network_connection_setup.c','src/network_handshake.c','src/network_route_insert.c','src/network_storage.c','src/network_connection_open.c','src/network_observer_tick.c','include/halo2/network_observer_tick.h','tests/network_observer_tick_oracle.py','src/network_observer_retry.c','src/network_observer_selection.c','include/halo2/network_observer_selection.h','src/network_observer_query.c','src/network_observer.c','src/network_resolution.c','tests/network_observer_selection_oracle.py','tests/network_resolution_oracle.py','tests/network_observer_query_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,boundary_coverage=coverage,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Session maintenance through actual shutdown guard and observer request/tick integration: original instructions and actual query/detach/resolution/retry/set-state callees, full guest memory/scratch and consumer callback masks. Clock callbacks mutate flags/config and override. Session states 0..10 and signed edge cases, identity and activity gates, negative/empty/three-peer counts and callback changes to session state/count are covered. Request/tick recursion and state5 connection open, handshake enqueue, stream reset and inactive storage clear execute. Fresh writer avoids packet flush; queued storage covered in connection-open suite. Not gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
