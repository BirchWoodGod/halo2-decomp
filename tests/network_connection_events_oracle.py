#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks,Provider
Call=C.CFUNCTYPE(None,C.c_void_p,*([C.c_uint32]*6))
class Callbacks(C.Structure):_fields_=[('context',C.c_void_p),('invoke',Call)]
P=lambda n:struct.pack('<I',n&0xffffffff)
W=lambda n:struct.pack('<H',n&0xffff)
def suite(h):
    conn=h.table;stream=conn+0x1000;provider=conn+0x2000;other=conn+0x2100;objects=conn+0x2400;vt=conn+0x2500;scratch=conn+0x3000;rng=random.Random(0x88db0)
    original=[];native=[];frame={};coverage=dict(ticks=0,observed=0,feedback=0,early=0,completed=0,retired=0,out_of_order=0,mutations=0,disabled=0)
    targets={0x3000800:('observed',3),0x3000820:('feedback',3),0x3000840:('early',1),0x3000860:('completed',2)}
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,kind,obj,args):
        log.append((kind,obj,args,bytes(read(conn,0x100)),bytes(read(stream,0x980)),bytes(read(provider,0x180))))
        if log is original:coverage[kind]+=1
        if kind=='ticks':
            write(0x4e6398,P(0x11223344+case));write(0x4e639c,P(0x55667788+case))
            if case%7==0:write(0x510548,b'\1');write(0x51054c,P(1000))
            return 1000
        if case%5==0:
            write(conn+0x3c,P(other));write(conn+0x40,P(objects+4));write(conn+0x44,P(0x12345678));write(conn+16,P(123));write(0x4d87d8,P(stream+0x400))
            if log is original:coverage['mutations']+=1
        if kind=='completed' and case%11==0:
            write(conn+0x24+8,P(0));write(stream+0x968,P(700));write(0x4cf72c,P(100))
        return 0
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks',0,()));clock=Operations(None,tick,Provider())
    call=Call(lambda ctx,fn,obj,n,a,b,c:event(h.read,nw,native,targets[fn][0],obj,(a,b,c)[:n]));callbacks=Callbacks(None,call)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x88db0:frame['base']=sp-72;u.mem_write(sp-72,seed[:72]);return
        if at==0x88fc1:frame['result']=bytes(u.mem_read(frame['base'],72));return
        if at==0x96d43:coverage['retired']+=1;return
        if at==0x96684:coverage['out_of_order']+=1;return
        if at==0x3314b0:kind='ticks';n=0;obj=0
        else:kind,n=targets[at];obj=u.reg_read(X.UC_X86_REG_ECX)
        args=struct.unpack('<'+'I'*n,u.mem_read(sp+4,n*4)) if n else ()
        value=event(u.mem_read,u.mem_write,original,kind,obj,args)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4+4*n)
    for at,(_,n) in targets.items():h.u.mem_write(at,b'\xc2'+struct.pack('<H',4*n))
    for at in [0x88db0,0x88fc1,0x3314b0,0x96d43,0x96684,*targets]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_connection_dispatch_events;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Callbacks),C.c_uint32,C.c_uint32];fn.restype=None
    for case in range(1024):
        original.clear();native.clear();frame.clear();h.write(conn,bytes(0x100));h.write(stream,bytes(0x980));h.write(provider,bytes(0x200));h.write(conn+0x48,bytes([0 if case%17==0 else 8]));h.write(conn+0x54,P(4));h.write(conn+0x40,P(objects if case%3 else 0));h.write(conn+0x44,P(case));h.write(conn+0x20,P(case%4));h.write(conn+0x3c,P(provider if case%4 else 0));h.write(0x4d87d8,P(stream))
        if case%17==0:coverage['disabled']+=1
        for j in range(8):h.write(objects+j*4,P(vt))
        for offset,target in [(8,0x3000800),(12,0x3000820),(24,0x3000840),(28,0x3000860)]:h.write(vt+offset,P(target))
        for j in range(3):h.write(conn+0x24+j*8,P([4,8,12][(case+j)%3])+P(objects+8+j*4))
        for p in [provider,other]:
            h.write(p+12,P(case%5))
            for j in range(4):h.write(p+16+j*8,P([4,8,12,0][(case+j)%4])+P(objects+8+j*4))
        oldest=100;latest=108;done=oldest+[0,1,3,8][case//4%4];head=case%8
        for off,val in [(0x2c,8),(0x30,latest),(0x34,oldest),(0x38,8),(0x3c,head),(0x40,8),(0x44,done),(0x48,8000),(0x94c,done+1),(0x974,2000 if case%2 else 0),(0x978,0),(0x968,[0,1,100,0xffffffff,0x7fffffff,0x80000000][case%6])]:h.write(stream+off,P(val))
        for j in range(8):
            p=stream+0x14c+j*16;h.write(p,P(900));h.write(p+4,P(100+j));h.write(p+8,P([0,100,1000,0xffffffff][(case+j)%4]));h.write(p+14,W([0,1,3,4,8,1,0,3][(case+j)%8]))
        h.write(0x510548,bytes([0 if case%3 else 255]));h.write(0x51054c,P(1000));h.write(0x4e6398,P(0x11223344));h.write(0x4e639c,P(0x55667788));h.write(0x4cf6f0,P(100));h.write(0x4cf6f4,P(0));h.write(0x4cf71c,P(0));h.write(0x4cf720,P(1000));h.write(0x4cf72c,P([0,100,0xffffffff][case%3]));h.write(0x4cf728,struct.pack('<f',[0,0.5,1,1.5,-1,float('inf'),float('nan')][case%7]))
        seed=rng.randbytes(76);h.write(scratch,seed)
        def run():
            fn(h.memory,C.byref(clock),C.byref(callbacks),conn,scratch)
            assert h.read(scratch,72)==frame['result'],(case,'frame',h.read(scratch,72).hex(),frame['result'].hex())
            nw(scratch,seed)
        h.call('dispatch_events',0x88db0,dict(esi=conn),[],run);assert original==native,(case,'callbacks')
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-events-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_connection_events.c','include/halo2/network_connection_events.h','src/network_connection_iteration.c','include/halo2/network_connection_iteration.h','src/network_stream_events.c','include/halo2/network_stream_events.h','tests/network_connection_events_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Connection event dispatch with actual queue completion/poll/retirement, component iterator and elapsed callees. Full persistent memory, complete original 72-byte frame and virtual/SDK callback snapshots. Acknowledgment/out-of-order/completion/timeout, component and observer mutation, captured stream across pointer mutation, float thresholds and incoming boolean-word padding. Nested poll scratch excluded. SDK ticks and virtual implementations controlled; default float rounding. No live packets or whole connection update/gameplay.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
