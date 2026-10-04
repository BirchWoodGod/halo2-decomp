#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_send_oracle import Ops
from network_state_oracle import Operations,Ticks,Provider
from network_stream_reserve_oracle import Callbacks as ReserveCallbacks,Blocked
P=lambda n:struct.pack('<I',n&0xffffffff)
Invoke=C.CFUNCTYPE(C.c_uint32,C.c_void_p,*([C.c_uint32]*7))
Diagnostic=C.CFUNCTYPE(None,C.c_void_p,*([C.c_uint32]*4))
class Formatting(C.Structure):_fields_=[('context',C.c_void_p),('vsnprintf',Diagnostic)]
class Callbacks(C.Structure):_fields_=[('context',C.c_void_p),('invoke',Invoke),('formatting',Formatting)]
def suite(h):
    conn=h.table;stream=conn+0x1000;buffer=conn+0x1100;provider=conn+0x1800;objects=conn+0x2000;vt=conn+0x2200;observer=conn+0x2300;queue=conn+0x3000;endpoint=conn+0x4000;secondary=conn+0x5000;out=conn+0x5300;scratch=conn+0x6000
    targets=[0x3000800+i*0x10 for i in range(4)];rng=random.Random(0x88980);frame={};original=[];native=[]
    coverage=dict(budget=0,write=0,observer=0,blocked=0,ticks=0,submitted=0,budget_abort=0,write_abort=0,padding=0,mutations=0)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,fn,obj,args):
        get=lambda p:struct.unpack('<I',read(p,4))[0]
        log.append((fn,obj,args,bytes(read(conn,0xf8)),bytes(read(stream,0x40)),bytes(read(buffer,0x640)),bytes(read(queue,0x980))))
        name=['budget','write','observer','blocked'][targets.index(fn)] if fn in targets else 'ticks'
        if log is original:coverage[name]+=1
        index=(obj-objects)//8
        if name=='budget':
            if case%23==0:
                write(conn+0x3c,P(0));write(stream+8,P([1,2,4,16][case//23%4]))
                if log is original:coverage['mutations']+=1
            if case%13==0:return args[0]+1
            return [0,1,7,16,31,64][(case+index)%6]
        if name=='write':
            sequence,bs,bits,remaining=args
            pos=get(bs+16)
            if case%11==0:write(bs+16,P(get(bs+4)*8));return 255
            count=min(bits,32)
            for i in range(count):
                p=get(bs)+(pos+i)//8;b=read(p,1)[0];write(p,bytes([b|(((index+case)>> (i%8)&1)<<((pos+i)%8))]))
            write(bs+16,P(pos+count))
            if case%17==0:
                write(conn+0x40,P(observer));write(conn+0x1c,b'\x91')
                if log is original:coverage['mutations']+=1
            return 0xabcd0000|([0,1,255][(case+index)%3])
        if name=='observer':
            write(conn+0x90,P(args[1]));return 0
        if name=='blocked':
            if case%29==0:write(queue+0x94c,P(0xffffff00))
            return 255 if case%7==0 else 0
        return 1500
    invoke=Invoke(lambda ctx,fn,obj,count,a,b,c,d:event(h.read,nw,native,fn,obj,(a,b,c,d)[:count]))
    diag=Diagnostic(lambda *args:(_ for _ in ()).throw(AssertionError('unexpected diagnostic')))
    callbacks=Callbacks(None,invoke,Formatting(None,diag))
    blocked=Blocked(lambda ctx,fn,obj,reason:event(h.read,nw,native,fn,obj,(reason,)));reservation=ReserveCallbacks(None,blocked)
    ticks=Ticks(lambda ctx:event(h.read,nw,native,0x3314b0,0,()));clock=Operations(None,ticks,Provider());send=Ops()
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x88980:frame['base']=((sp-4)&~7)-0x74c;u.mem_write(frame['base'],seed);return
        if at==0x88d16:frame['result']=bytes(u.mem_read(frame['base'],0x74c));return
        if at in [0x88b13,0x88b7a,0x88bb0,0x931a0]:
            if at==0x88b13:frame['budget_ok']=True
            elif at==0x88b7a:frame['wrote']=True
            else:coverage['padding' if at==0x88bb0 else 'submitted']+=1
            return
        count=[2,4,3,1][targets.index(at)] if at in targets else 0
        args=struct.unpack('<'+'I'*count,u.mem_read(sp+4,count*4)) if count else ()
        result=event(u.mem_read,u.mem_write,original,at,u.reg_read(X.UC_X86_REG_ECX) if count else 0,args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4+count*4)
    for t,n in zip(targets,[8,16,12,4]):h.u.mem_write(t,b'\xc2'+struct.pack('<H',n))
    for at in [0x88980,0x88d16,0x88b13,0x88b7a,0x88bb0,0x931a0,0x3314b0,*targets]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_connection_build_packet;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(ReserveCallbacks),C.POINTER(Callbacks),C.c_uint8,C.c_uint32,C.c_uint32,C.c_uint8]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];fn.restype=None
    for case in range(1536):
        original.clear();native.clear();frame.clear();h.write(conn,rng.randbytes(0xf8));h.write(stream,rng.randbytes(0x40));h.write(buffer,rng.randbytes(0x640));h.write(provider,bytes(0x80));h.write(queue,rng.randbytes(0x980));h.write(endpoint,bytes(0x588));h.write(secondary,rng.randbytes(0x200));h.write(out,rng.randbytes(12))
        h.write(conn,P(endpoint));h.write(conn+16,P(0));h.write(conn+0x20,P(case%4));h.write(conn+0x3c,P(provider if case%5 else 0));h.write(conn+0x40,P(observer if case%3 else 0));h.write(conn+0x44,P(0));h.write(conn+0x54,P([0,1,3][case%3]));h.write(conn+0x70,P(0x0a010203));h.write(conn+0x82,b'\x04\0')
        h.write(provider+12,P(case//4%4));h.write(provider+0x31,bytes([case%2]));h.write(observer,P(vt+0x40));h.write(vt+0x40,P(targets[2]));h.write(vt+12,P(targets[0]));h.write(vt+16,P(targets[1]));h.write(vt+4,P(targets[3]))
        for i in range(6):
            obj=objects+i*8;h.write(obj,P(vt));entry=conn+0x24+i*8 if i<3 else provider+0x10+(i-3)*8;h.write(entry,P((case+i)%4)+P(obj))
        h.write(stream,P(buffer)+P([0,8,32,128,512,1536][case//3%6]));h.write(queue,P(vt))
        for off,v in [(0x2c,8),(0x30,100),(0x34,100),(0x38,8),(0x3c,0),(0x40,0),(0x44,100),(0x94c,100)]:h.write(queue+off,P(v))
        h.write(0x4d87d4,P(conn));h.write(0x4d87d8,P(queue));h.write(0x510548,bytes([case//3%2]));h.write(0x51054c,P(1500));h.write(0x4d8b18,b'\1\1')
        for off in [0x228,0x3d8]:
            h.write(endpoint+off+0x10,P(100));h.write(endpoint+off+0x20,P(100))
        seed=rng.randbytes(0x74c);saved=seed+rng.randbytes(0x1f84-0x74c);h.write(scratch,saved)
        reserve=case%2;fill=case//2%2;extra=[0,7,31,512][case//5%4];outputs=[out if case%7 else 0,out+4 if case%11 else 0,out+8 if case%13 else 0]
        if case%19==0:outputs=[stream+4,out,out]
        def run():
            workspace=(C.c_uint8*28)()
            fn(h.memory,C.byref(clock),C.byref(send),C.byref(reservation),C.byref(callbacks),reserve,conn,stream,fill,extra,secondary,*outputs,scratch,workspace)
            actual=h.read(scratch,0x74c);expected=frame['result']
            if actual!=expected:
                diff=[i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b];raise AssertionError((case,'locals',diff[:30]))
            nw(scratch,saved)
        h.call('build_packet',0x88980,dict(eax=reserve),[conn,stream,fill,extra,secondary,*outputs],run);assert original==native,(case,'callbacks')
        if 'budget_ok' not in frame and case%7:coverage['budget_abort']+=1
        if frame.get('wrote') and any(x[0]==targets[1] for x in original) and case%11==0:coverage['write_abort']+=1
    assert all(coverage.values()),coverage
    return coverage

def format_suite(h):
    destination=h.table+0x10000;arguments=destination+0x200;rng=random.Random(0xb66f0);original=[];native=[]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,dst,capacity,fmt,args):
        values=bytes(read(args,8));log.append((dst,capacity,fmt,values,bytes(read(dst,256))))
        write(dst,bytes([case&255])*[0,1,254,255][case%4])
    callback=Diagnostic(lambda ctx,dst,capacity,fmt,args:event(h.read,nw,native,dst,capacity,fmt,args));ops=Formatting(None,callback)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);dst,capacity,fmt,args=struct.unpack('<4I',u.mem_read(sp+4,16));event(u.mem_read,u.mem_write,original,dst,capacity,fmt,args)
        u.reg_write(X.UC_X86_REG_EAX,[0,255,0xffffffff][case%3]);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    handle=h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x321980,end=0x321980)
    fn=h.lib.h2_format_string_256;fn.argtypes=[C.POINTER(Memory),C.POINTER(Formatting)]+[C.c_uint32]*3;fn.restype=C.c_uint32
    for case in range(512):
        original.clear();native.clear();h.write(destination,rng.randbytes(256));a=rng.getrandbits(32);b=rng.getrandbits(32);h.write(arguments,P(a)+P(b))
        h.u.mem_write(0x2008004,P(0x453e78)+P(a)+P(b))
        h.call('format_string_256',0xb66f0,dict(esi=destination),[],lambda:fn(h.memory,C.byref(ops),destination,0x453e78,arguments),0xffffffff);assert original==native,case
    h.u.hook_del(handle)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-build-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:
        coverage=suite(h);format_suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/format_string.c','include/halo2/format_string.h','src/network_connection_build.c','include/halo2/network_connection_build.h','src/network_connection_packet.c','include/halo2/network_connection_packet.h','tests/network_connection_build_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original packet builder with actual reservation, iterator, bitstream writers, packet submission and accounting callees. Full memory, original0x74c local frame, callback order and state. Controlled virtual components/observer/blocked/ticks; empty socket endpoints. Zero/large budgets, inline/provider flags, early exits, fill bits, raw boolean padding, output aliasing and component mutation. Valid mapped buffers/component indices/alignment; Formatter wrapper separately compared in512 cases with controlled CRT output/return and forced terminator. Oversized builder padding and live networking not exercised.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
