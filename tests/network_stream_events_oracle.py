#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks,Provider
P=lambda v:struct.pack('<I',v&0xffffffff)
W=lambda v:struct.pack('<H',v&0xffff)
def suite(h):
    stream=h.table;out=stream+0x1000;scratch=out+32;queue=out+0x100;rng=random.Random(0x96b00)
    original=[];native=[];coverage=dict(ack=0,timeout=0,complete=0,out_of_order=0,retired=0,ticks=0,aliases=0,empty=0)
    sites={0x96b52:'ack',0x96bc0:'timeout',0x96c29:'complete',0x96684:'out_of_order',0x96d43:'retired'}
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log):
        log.append(bytes(read(stream,0x980)))
        if case%5==0:write(stream+0x978,P(2000));write(0x4cf720,P(2100))
        if case%7==0:write(0x510548,b'\1');write(0x51054c,P(1001))
        return 1000+len(log)
    cb=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations(None,cb,Provider())
    def hook(u,at,size,ctx):
        if at in sites:coverage[sites[at]]+=1;return
        coverage['ticks']+=1;sp=u.reg_read(X.UC_X86_REG_ESP);v=event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,v);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x3314b0,*sites]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    bindings=[('record',2,C.c_uint32),('complete_next',6,C.c_uint8),('poll_event',6,C.c_uint32),('retire_next',5,C.c_uint8)]
    fns={}
    for name,count,result in bindings:
        f=getattr(h.lib,'h2_network_stream_'+name);f.restype=result
        f.argtypes=[C.POINTER(Memory)]+([] if name=='record' else [C.POINTER(Operations)])+[C.c_uint32]*(count if name=='record' else count-1)
        fns[name]=f
    advance=h.lib.h2_network_sequence_queue_advance;advance.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];advance.restype=None
    def setup(case):
        original.clear();native.clear();h.write(stream,bytes(0x980));h.write(out,rng.randbytes(40))
        oldest=[0,100,0xfffffff0,0x7ffffff0,0x80000010][case%5];latest=(oldest+8)&0xffffffff;done=(oldest+[0,1,3,7,8][case//5%5])&0xffffffff
        head=case%8;h.write(stream+0x2c,P(8));h.write(stream+0x30,P(latest));h.write(stream+0x34,P(oldest));h.write(stream+0x38,P(8));h.write(stream+0x3c,P(head));h.write(stream+0x40,P(8));h.write(stream+0x44,P(done));h.write(stream+0x48,P(rng.getrandbits(32)));h.write(stream+0x94c,P(done+1+(100 if case%9==0 else 0)));h.write(stream+0x974,P([0,500,2000][case%3]));h.write(stream+0x978,P([0,100,0x7fffffff][case//3%3]))
        for j in range(8):
            record=stream+0x14c+j*16;h.write(record,P([0,900,1000,0xffffffff][(case+j)%4]));h.write(record+4,P(rng.randrange(2048)));h.write(record+8,P(rng.getrandbits(32)));h.write(record+14,W([0,1,2,3,4,8,16,0xffff][(case+j)%8]))
        h.write(0x510548,bytes([0 if case%2 else 255]));h.write(0x51054c,P(1000));h.write(0x4cf6f0,P(100));h.write(0x4cf6f4,P(100));h.write(0x4cf71c,P([0,100,0xffffffff][case%3]));h.write(0x4cf720,P(1000))
        return oldest,done,head
    for case in range(1024):
        oldest,done,head=setup(case)
        sequence=(oldest+[-1,0,1,4,8,9][case%6])&0xffffffff
        if case%7==0:h.write(stream+0x40,P(0));coverage['empty']+=1
        f=fns['record'];h.call('record',0x966d0,dict(ecx=stream,eax=sequence),[],lambda:f(h.memory,stream,sequence),0xffffffff)
        h.write(queue,bytes(32));h.write(queue+12,P(oldest));h.write(queue+16,P([1,8,0xfffffff8][case%3]));h.write(queue+20,P([0,7,0x7fffffff,0xffffffff][case%4]));h.write(queue+24,P([0,1,8,0xffffffff][case%4]))
        h.call('advance',0x1a4840,dict(esi=queue,ebx=sequence),[],lambda:advance(h.memory,queue,sequence))
    for name in ['complete_next','poll_event','retire_next']:
        for case in range(1024):
            oldest,done,head=setup(case);kind=out;sequence=out+4;size=out+8;elapsed=out+12
            record=stream+0x14c+((done-oldest+head)%8)*16
            if name!='retire_next' and case%4==0:
                size=record+4 if case%8==0 else sequence;elapsed=0x510548 if case%16==0 else record+8;coverage['aliases']+=1
            if name=='complete_next':
                f=fns[name];h.call(name,0x96b00,dict(edi=stream),[kind,sequence,size,elapsed],lambda:f(h.memory,C.byref(clock),stream,kind,sequence,size,elapsed),255)
            elif name=='poll_event':
                f=fns[name];saved=h.read(scratch,4)
                def run():
                    result=f(h.memory,C.byref(clock),stream,sequence,size,elapsed,scratch);nw(scratch,saved);return result
                h.call(name,0x965e0,dict(eax=stream),[sequence,size,elapsed],run,0xffffffff)
            else:
                f=fns[name];force=[0,1,255][case%3]
                h.call(name,0x96ce0,{},[stream,force,kind,sequence],lambda:f(h.memory,C.byref(clock),stream,force,kind,sequence),255)
            assert original==native,(name,case)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-stream-events-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_stream_events.c','include/halo2/network_stream_events.h','tests/network_stream_events_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original stream record lookup, queue retirement, completion, event polling and retirement predicate. Full persistent memory, returns and clock snapshots; acknowledgment/timeout/out-of-order events, signed arithmetic, wrap and aliased output stores. Engine callees intact, SDK clock controlled; poll scratch word excluded. Valid mapped queues with nontrapping divisors; not live packets or complete connection update.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
