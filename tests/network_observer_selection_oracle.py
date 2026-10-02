#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations as Clock
from network_send_oracle import Ops as SendOps
from network_connection_oracle import Callbacks
from network_registration_oracle import Operations as Registration,Call
from network_observer_query_oracle import Query,QueryOps
from network_resolution_oracle import Resolve,Status,Resolution
from message_dispatch_oracle import Platform

def suite(h):
    rng=random.Random(0x78330);observer=h.table;writer=observer+0x3000;conn=observer+0x4000;local=observer+0x5000;querylocal=local+32;resolve_local=local+64;packet=observer+0x6000
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    original=[];native=[];frames={};coverage={};iteration=0;entry=0
    def event(read,write,events,kind,*args):
        observed=args[:2]+(bytes(read(args[2],4)),) if kind=='resolve' else args
        events.append((kind,observed,bytes(read(observer,0x1800)),bytes(read(0x4cf7d4,0x100))))
        if events is original:coverage[kind]=coverage.get(kind,0)+1
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
    clock=Clock();send=SendOps();codec=Platform();callbacks=Callbacks()
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x7acf0:frames['query']=sp-4;return
        if at in [0x7ad15,0x7ad19,0x7ad20,0x7ad27,0x7ad2e]:frames['query_bytes']=bytes(u.mem_read(frames['query'],4));return
        if at==0x784a0:frames['mark']=sp+4;return
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
    for at in [0x7acf0,0x7ad15,0x7ad19,0x7ad20,0x7ad27,0x7ad2e,0x784a0,0x78551,0x7adf0,0x7ae67,0x7acc0,0x7ace4,0x783d0,0x78472,0x7848d,0x3cd0ec,0x3cd35a,0x3cd344,0x3cd34f]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_select_address;fn.restype=C.c_uint8;fn.argtypes=[C.POINTER(Memory),C.POINTER(QueryOps),C.POINTER(Resolution),C.POINTER(Clock),C.POINTER(SendOps),C.POINTER(Platform),C.POINTER(Callbacks),C.POINTER(Registration)]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)]
    selected=set()
    for iteration in range(2048):
        original.clear();native.clear();frames.clear();h.write(observer,rng.randbytes(0x1800));h.write(writer,bytes(0x700));h.write(observer+8,pack(writer));h.write(conn,bytes(0x400));h.write(0x4d87d4,pack(conn))
        for k in range(4):h.write(conn+k*0xf8+0x54,pack(2))
        index=iteration%4;entry=observer+0xa8+index*0x528
        h.write(entry+12,pack(index));h.write(entry+9,bytes([iteration%16]));h.write(entry+0x38,pack(iteration//480%16));h.write(entry+0x3c,pack(0xffffffff))
        h.write(entry+0x5c,pack(0x00123456)+bytes(12)+struct.pack('<HH',1000,4 if iteration%3 else 0))
        for k in range(4):
            slot=observer+k*36;h.write(slot+0x14,pack(1 if iteration%17 else 0));h.write(slot+0x18,pack(k if iteration%19 else 0xffffffff));h.write(slot+0x1c,pack(0 if iteration%23 else 1))
            h.write(0x4cf7d4+k*32,b'\1\0\0\0'+pack(0)+rng.randbytes(24))
        incoming=rng.randbytes(16);query_seed=rng.randbytes(4);resolve_seed=rng.randbytes(28);h.write(local,incoming);h.write(querylocal,query_seed);h.write(resolve_local,resolve_seed)
        def run():
            value=fn(h.memory,C.byref(query_ops),C.byref(resolution),C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),C.byref(registration),observer,index,querylocal,local,resolve_local,packet,(C.c_uint8*28)())
            assert h.read(querylocal,4)==frames.get('query_bytes',query_seed),(iteration,'query')
            expected=incoming[:12]+frames.get('mark_bytes',pack(0) if 'mark' in frames else incoming[12:])
            assert h.read(local,16)==expected,(iteration,'detach')
            expected=frames.get('lookup_bytes',resolve_seed[:20])+frames.get('peer_bytes',resolve_seed[20:24])+frames.get('ready_bytes',resolve_seed[24:])
            assert h.read(resolve_local,28)==expected,(iteration,'resolution')
            if value and h.u32(entry+0x3c)<4:selected.add(h.u32(entry+0x3c))
            nw(querylocal,query_seed);nw(local,incoming);nw(resolve_local,resolve_seed);return value
        h.call('observer_select_address',0x78330,dict(eax=index),[observer],run,255)
        assert original==native,iteration
    assert selected==set(range(4)),selected
    assert all(coverage.get(k) for k in ['resolve','query','ready','release']),coverage
    coverage['selected_consumers']=sorted(selected)
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-selection-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_selection.c','include/halo2/network_observer_selection.h','src/network_observer_query.c','src/network_observer.c','src/network_resolution.c','tests/network_observer_selection_oracle.py','tests/network_resolution_oracle.py','tests/network_observer_query_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,boundary_coverage=coverage,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Actual query/detach/resolution callees. Full guest memory, AL and scratch, all four selected consumers, SDK failures, masks and callback mask/identity mutation. Connections state2 and writer inactive; no close/flush in this fixture. SDK query/resolve/prepare/release controlled; no live networking or gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
