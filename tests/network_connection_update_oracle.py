#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops
from message_dispatch_oracle import NativeCodec,Platform
from network_connection_oracle import Callbacks as CloseCallbacks,Closed
from network_connection_build_oracle import Callbacks as BuildCallbacks,Invoke,Formatting,Diagnostic
from network_stream_reserve_oracle import Callbacks as ReserveCallbacks,Blocked
from network_connection_events_oracle import Callbacks as EventCallbacks,Call
P=lambda n:struct.pack('<I',n&0xffffffff)
Update=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint32))
class UpdateCallbacks(C.Structure):_fields_=[('context',C.c_void_p),('invoke',Update)]
class Context(C.Structure):_fields_=[(n,C.POINTER(t)) for n,t in [('clock',Operations),('send',Ops),('codec',Platform),('close',CloseCallbacks),('reserve',ReserveCallbacks),('build',BuildCallbacks),('events',EventCallbacks),('update',UpdateCallbacks)]]
def suite(h,endpoint_mode=False):
    conn=h.table;config=conn+0x200;provider=conn+0x300;objects=conn+0x500;vt=conn+0x600;observer=conn+0x700;queue=conn+0x1000;endpoint=conn+0x2000;writer=conn+0x3000;table=conn+0x4000;scratch=conn+0x6000
    kinds=[('closecheck',1),('active',1),('plan',10),('budget',2),('write',4),('sent',3),('blocked',1),('observed',3),('feedback',3),('early',1),('complete',2),('closed',1)]
    targets={0x3000800+i*0x10:x for i,x in enumerate(kinds)};target={n:t for t,(n,c) in targets.items()};rng=random.Random(0x883c0);original=[];native=[];frame={};errors=[]
    coverage={n:0 for n,c in kinds};coverage.update(ticks=0,handshake=0,close=0,build=0,dispatch=0,mutations=0)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def norm(p,log):
        base=frame['base'] if log is original else scratch
        return scratch+p-base if base<=p<base+0x864 else p
    def event(read,write,log,kind,obj,args):
        get=lambda p:struct.unpack('<I',read(p,4))[0]
        normalized=tuple(norm(a,log) for a in args)
        log.append((kind,obj,normalized,bytes(read(conn,0xf8)),bytes(read(queue,0x980)),bytes(read(writer,0x700))))
        if log is original:coverage[kind]+=1
        if kind=='closecheck':
            write(args[0],P(6))
            if case%31==0:
                write(conn+0x54,P(2))
                if log is original:coverage['mutations']+=1
            return 255 if case%17==0 else 0xabcd0000
        if kind=='active':
            write(args[0],bytes([case%2]))
            if case%37==0:
                write(conn+0x54,P(2))
                if log is original:coverage['mutations']+=1
            return 255 if case%5 else 0
        if kind=='plan':
            _,a,b,c,reserve,fill,size,extra,limit,buffer=args
            write(reserve,bytes([case//3%2]));write(fill,bytes([case//4%2]));write(size,P([8,32,128,1536][case%4]));write(extra,P([0,7,31,512][case//6%4]));write(buffer,bytes([case&255])*512)
            if case%19==0:
                write(conn+0x48,b'\0');write(conn+0x54,P(2))
                if log is original:coverage['mutations']+=1
            return 0xabcd0000|(0 if case%7==0 else 1)
        if kind=='budget':return [0,1,7,16,31][case%5]
        if kind=='write':
            sequence,bs,bits,remaining=args;write(bs+16,P(get(bs+16)+bits));return 1
        if kind=='sent':return 0
        if kind=='blocked':return 255 if case%11==0 else 0
        if kind=='ticks':
            if endpoint_mode and case%43==0:write(endpoint+0x20,P(1))
            return 200
        if kind=='closed':
            if case%13==0:write(conn+0x70,P(0x11223344))
            return 0
        return 0
    def safe(read,write,log,kind,obj,args):
        try:return event(read,write,log,kind,obj,args)
        except Exception as exc:errors.append(repr(exc));return 0
    clockfn=Ticks(lambda ctx:safe(h.read,nw,native,'ticks',0,()));clock=Operations(None,clockfn,Provider());send=Ops()
    closed=Closed(lambda ctx,f,a:safe(h.read,nw,native,'closed',0,(a,)));close=CloseCallbacks(None,closed)
    blocked=Blocked(lambda ctx,f,o,a:safe(h.read,nw,native,'blocked',o,(a,)));reserve=ReserveCallbacks(None,blocked)
    invoke=Invoke(lambda ctx,f,o,n,a,b,c,d:safe(h.read,nw,native,targets[f][0],o,(a,b,c,d)[:n]));diag=Diagnostic(lambda *args:errors.append('unexpected diagnostic'));build=BuildCallbacks(None,invoke,Formatting(None,diag))
    ev=Call(lambda ctx,f,o,n,a,b,c:safe(h.read,nw,native,targets[f][0],o,(a,b,c)[:n]));events=EventCallbacks(None,ev)
    updatefn=Update(lambda ctx,f,o,n,args:safe(h.read,nw,native,targets[f][0],o,tuple(args[:n])));update=UpdateCallbacks(None,updatefn)
    codec=Platform();codec_context=NativeCodec(h.memory,C.pointer(clock),scratch+0x5000);init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(codec_context))
    context=Context(*[C.pointer(x) for x in [clock,send,codec,close,reserve,build,events,update]])
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32];h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x883c0:frame['base']=sp-0x864;u.mem_write(frame['base'],frame.get('result',saved[:0x864]));return
        if at==0x88643:frame['result']=bytes(u.mem_read(frame['base'],0x864));return
        if at==0x88980:coverage['build']+=1;u.mem_write(((sp-4)&~7)-0x74c,saved[0x864:0xfb0]);return
        if at==0x88db0:
            coverage['dispatch']+=1
            # Entry local frame is 72 bytes, before saved registers.
            u.mem_write(sp-72,saved[0x27e8:0x2830]);return
        if at==0x890b0:coverage['handshake']+=1;u.mem_write(sp-8,saved[0x2834:0x283c]);return
        if at==0x88650:coverage['close']+=1;u.mem_write(sp-12,saved[0x283c:0x2848]);return
        kind,n=targets[at] if at in targets else ('ticks',0)
        args=struct.unpack('<'+'I'*n,u.mem_read(sp+4,n*4)) if n else ();obj=u.reg_read(X.UC_X86_REG_ECX) if n and kind!='closed' else 0
        value=safe(u.mem_read,u.mem_write,original,kind,obj,args);u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4+n*4)
    for t,(kind,n) in targets.items():h.u.mem_write(t,b'\xc2'+struct.pack('<H',n*4))
    for at in [0x883c0,0x88643,0x88980,0x88db0,0x890b0,0x88650,0x3314b0,*targets]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_endpoint_update if endpoint_mode else h.lib.h2_network_connection_update;fn.argtypes=[C.POINTER(Memory),C.POINTER(Context),C.c_uint32,C.c_uint32,C.POINTER(C.c_uint8)];fn.restype=None
    for case in range(1024):
        original.clear();native.clear();frame.clear();errors.clear();h.write(conn,rng.randbytes(0xf8));h.write(provider,bytes(0x80));h.write(queue,bytes(0x980));h.write(endpoint,bytes(0x588));h.write(writer,bytes(0x700));h.write(writer+8,P(endpoint)+P(table))
        h.write(conn,P(endpoint)+P(writer));h.write(conn+12,P(config));h.write(config,P(10)+P(10)+P([100,1000][case%2])+P([100,1000][case//2%2]));h.write(conn+16,P(0));h.write(conn+0x20,P(2));h.write(conn+0x3c,P(provider if case%5 else 0));h.write(conn+0x40,P(observer if case%3 else 0));h.write(conn+0x44,P(0));h.write(conn+0x48,P(8 if case%2 else 0));h.write(conn+0x54,P([0,1,2,3,4,5,8,0xffffffff][case%8]));h.write(conn+0x70,P(0x0a010203));h.write(conn+0x82,b'\x04\0');h.write(conn+0x84,bytes([case//8%2]));h.write(conn+0x88,P(100));h.write(conn+0x8c,P(100));h.write(conn+0x90,P(0));h.write(conn+0x94,P(0))
        h.write(provider+4,P(99)+P(target['closed']));h.write(provider+12,P(1));h.write(provider+0x31,bytes([case%2]))
        for i in range(3):
            h.write(objects+i*8,P(vt));entry=conn+0x24+i*8 if i<2 else provider+0x10;h.write(entry,P([0x1d,0x2d,0x3d][(case+i)%3])+P(objects+i*8))
        for off,name in [(4,'closecheck'),(8,'active'),(12,'budget'),(16,'write'),(24,'early'),(28,'complete')]:h.write(vt+off,P(target[name]))
        h.write(observer,P(vt+0x40))
        for off,name in [(0,'sent'),(8,'observed'),(12,'feedback'),(20,'plan')]:h.write(vt+0x40+off,P(target[name]))
        h.write(queue,P(vt+0x80));h.write(vt+0x84,P(target['blocked']))
        count=case//7%4
        for off,v in [(0x2c,8),(0x30,100+count),(0x34,100),(0x38,8),(0x3c,0),(0x40,count),(0x44,100),(0x94c,100),(0x974,1000),(0x978,1000),(0x968,10),(0x48,10)]:h.write(queue+off,P(v))
        for i in range(4):h.write(queue+0x14c+i*16,P(100)+P(10)+P(20)+b'\0\0'+bytes([1 if i==1 or (i==0 and case//29%2) else 0])+b'\0')
        h.write(0x4d87d4,P(conn));h.write(0x4d87d8,P(queue));h.write(0x510548,bytes([case//3%2]));h.write(0x51054c,P(200));h.write(0x4d8b18,b'\1\1');h.write(0x4cf6f0,P(1000));h.write(0x4cf6f4,P(1000));h.write(0x4cf728,struct.pack('<f',2.0));h.write(0x4cf72c,P(10))
        for off in [0x228,0x3d8]:h.write(endpoint+off+0x10,P(100));h.write(endpoint+off+0x20,P(100))
        if endpoint_mode:
            h.write(endpoint+0x20,P([0xffffffff,0,1,2,3][case%5]))
            for i in range(3):h.write(endpoint+0x24+i*32,P(0));h.write(endpoint+0x2c+i*32,bytes([(case+i)%2]));h.write(endpoint+0x30+i*32,h.read(conn+0x70,20))
        saved=rng.randbytes(0x4070);h.write(scratch,saved)
        def run():
            workspace=(C.c_uint8*28)();fn(h.memory,C.byref(context),endpoint if endpoint_mode else conn,scratch,workspace);assert not errors,errors
            actual=h.read(scratch,0x864);expected=bytearray(frame.get('result',saved[:0x864]))
            if coverage['build'] and frame.get('base'):
                p=struct.unpack_from('<I',expected,0x30)[0]
                if p==frame['base']+0x264:struct.pack_into('<I',expected,0x30,scratch+0x264)
            if actual!=expected:
                diff=[i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b];raise AssertionError((case,'locals',diff[:25]))
            nw(scratch,saved)
        h.call('endpoint_update' if endpoint_mode else 'connection_update',0x93090 if endpoint_mode else 0x883c0,dict(eax=conn),[endpoint] if endpoint_mode else [],run);assert original==native,(case,'callbacks',[(x[0],x[2]) for x in original],[(x[0],x[2]) for x in native])
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-update-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage={'connection':suite(h)};counts=dict(h.counts)
    finally:h.close()
    h=Harness(lib)
    try:coverage['endpoint']=suite(h,True);counts.update(h.counts)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_connection_update.c','include/halo2/network_connection_update.h','src/network_connection_build.c','include/halo2/network_connection_build.h','src/network_connection_packet.c','src/format_string.c','tests/network_connection_update_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original connection and endpoint updates, deferred closes, signed/reloaded route count, repeated connection entries and recovered handshake/close/iteration/build/stamp/event callees. Full persistent memory and original0x864 parent frame, normalizing only local buffer pointer. Virtual component/observer/closed/blocked and SDK clock controlled; actual message codec dispatch used with empty endpoints. Nested unspecified local seeds controlled. Not live sockets or playable game.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
