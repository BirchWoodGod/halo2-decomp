#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_observer_query_oracle import Query,QueryOps
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops,Send,Error
from message_dispatch_oracle import NativeCodec,Platform
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    session=h.table;observer=session+0x8000;writer=session+0xa000;table=session+0xb000;endpoint=session+0xc000;socket=session+0xc600;payload=session+0xd000;qs=payload+0x200;packet=session+0xe000
    rng=random.Random(0x62300);original=[];native=[];frame={};errors=[];coverage=dict(query=0,ticks=0,send=0,error=0,enqueue=0,mutations=0)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,kind,args):
        log.append((kind,args,bytes(read(session,0x78b8)),bytes(read(writer,0x700))))
        if log is original:coverage[kind]+=1
        if kind=='query':
            if case%7==0:
                write(session+0x7614,P(0));write(0x4cf494,P(0))
                if log is original:coverage['mutations']+=1
            return [0,1,2,2,2,3,4,0xffffffff][case//4%8]
        if kind=='ticks':
            if case%11==0:
                write(session+0x7614,P(0x80000000));write(0x4cf494,P(0));write(session+0x1c,P(0xabcdef01))
                if log is original:coverage['mutations']+=1
            return 1000+sum(x[0]=='ticks' for x in log)*10
        if kind=='send':
            if case%13==0:write(0x510548,b'\1');write(0x51054c,P(0x10203040));write(session+0x7610,P(0xffffffff))
            return 0xffffffff if case%5==0 else args[2]
        return 0x2733
    queryfn=Query(lambda ctx,ip:event(h.read,nw,native,'query',(ip,)));query=QueryOps(None,queryfn)
    tickfn=Ticks(lambda ctx:event(h.read,nw,native,'ticks',()));clock=Operations(None,tickfn,Provider())
    sendfn=Send(lambda ctx,handle,data,n,flags,addr,length:event(h.read,nw,native,'send',(handle,bytes(h.read(data,n)),n,flags,C.string_at(addr,28),length)));errfn=Error(lambda ctx:event(h.read,nw,native,'error',()));send=Ops(None,sendfn,errfn)
    codec=Platform();ctx=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(ctx))
    register=h.lib.h2_messages_register_session;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x62300:frame['payload']=((sp-4)&~7)-0x1b8;u.mem_write(frame['payload'],seed);return
        if at in [0x623c0,0x623d1]:frame['payload_bytes']=bytes(u.mem_read(frame['payload'],0x1b8));return
        if at==0x7acf0:frame['query']=sp+4;return
        if at==0x7b140:coverage['enqueue']+=1;return
        if at==0xb5110:u.mem_write(sp-28,bytes(28));return
        if at==0x3cd35a:
            ip=struct.unpack('<I',u.mem_read(sp+4,4))[0];value=event(u.mem_read,u.mem_write,original,'query',(ip,));purge=4
        elif at==0x3314b0:value=event(u.mem_read,u.mem_write,original,'ticks',());purge=0
        elif at==0x3cd718:value=event(u.mem_read,u.mem_write,original,'error',());purge=0
        else:
            handle,data,n,flags,addr,length=struct.unpack('<6I',u.mem_read(sp+4,24));value=event(u.mem_read,u.mem_write,original,'send',(handle,bytes(u.mem_read(data,n)),n,flags,bytes(u.mem_read(addr,28)),length));purge=24
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x62300,0x623c0,0x623d1,0x7acf0,0x7b140,0xb5110,0x3cd35a,0x3314b0,0x3cd254,0x3cd718]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_session_resend_join;fn.argtypes=[C.POINTER(Memory),C.POINTER(QueryOps),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform)]+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];fn.restype=None
    enqueue=h.lib.h2_message_writer_enqueue;enqueue.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform)]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];enqueue.restype=C.c_uint8
    for case in range(1536):
        original.clear();native.clear();frame.clear();h.write(session,rng.randbytes(0x78b8));h.write(observer,bytes(0x1000));h.write(writer,bytes(0x700));h.write(endpoint,bytes(0x588));h.write(session+4,P(writer)+P(observer));h.write(session+0x7420,P(case%2));h.write(writer+8,P(endpoint)+P(table))
        address=observer+0xa8+(case%2)*0x528+0x5c;h.write(address,P([0,0x123456,0x123456,0x7f000001][case%4])+bytes(12)+struct.pack('<HH',1000,[4,4,4,16][case//8%4]))
        h.write(session+0x7448,P(0x7f000002)+bytes(12)+struct.pack('<HH',1000,4));h.write(session+0x745c,bytes(0x1ac));h.write(session+0x745c,P(case%4));h.write(session+0x745c+0x160-12,P(case%3))
        h.write(session+0x7614,P([0,999,1000,1001,0xffffffff,0x80000000][case//3%6]));h.write(session+0x7610,P(0xffffffff if case%7==0 else case));h.write(0x4cf494,P([0,1,10,1000,0xffffffff,0x80000000][case//5%6]));h.write(0x510548,bytes([case//7%2]));h.write(0x51054c,P(1000));h.write(0x4d8b18,b'\1\1')
        h.write(endpoint+0x18,P(socket));h.write(socket,P(17))
        for off in [0x228,0x3d8]:h.write(endpoint+off+0x10,P(100));h.write(endpoint+off+0x20,P(100))
        seed=rng.randbytes(0x1b8);qseed=rng.randbytes(4);pseed=rng.randbytes(0x1828);h.write(payload,seed);h.write(qs,qseed);h.write(packet,pseed);workspace=(C.c_uint8*28)()
        # Preload a valid unrelated message/address to exercise actual flush/send.
        old=qs+16;oldpayload=old+32;h.write(old,P(0x7f000003)+bytes(12)+struct.pack('<HH',1001,4));h.write(oldpayload,bytes(8))
        assert enqueue(h.memory,C.byref(clock),C.byref(send),C.byref(codec),writer,old,11,8,oldpayload,packet,workspace);h.write(writer,h.read(writer,0x700));native.clear()
        def run():
            fn(h.memory,C.byref(query),C.byref(clock),C.byref(send),C.byref(codec),session,payload,qs,packet,workspace)
            assert h.read(payload,0x1b8)==frame['payload_bytes'],(case,'payload')
            nw(payload,seed);nw(qs,qseed);nw(packet,pseed)
        h.call('resend_join',0x62300,dict(ebx=session),[],run);assert original==native,(case,'callbacks')
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-join-retry-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_session_join_retry.c','include/halo2/network_session_join_retry.h','tests/network_session_join_retry_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original join-request resend with actual address/query, enqueue, join codec, flush/packet/send callees. Full persistent memory,0x1b8 original payload frame and SDK snapshots. Query/clock/send/error controlled; SDK query results/address gates, signed timing, count overflow and callback mutation. Disjoint query/packet scratch restored; payload independently compared. No live session join.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
