#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations
Blocked=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class Callbacks(C.Structure):_fields_=[('context',C.c_void_p),('blocked',Blocked)]
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    stream=h.table;vt=stream+0x1000;scratch=vt+0x100;target=0x3000800;rng=random.Random(0x96510);frame={};original=[];native=[]
    coverage=dict(callbacks=0,mutations=0,retire=0,reserved=0,failed=0,blocked=0)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,fn,obj,reason):
        log.append((fn,obj,reason,bytes(read(stream,0x980))))
        if log is original:coverage['callbacks']+=1
        if case%5==0:
            write(stream+0x94c,P(108));write(stream+0x44,P(104));write(stream+0x48,P(0xfffffffe))
            if log is original:coverage['mutations']+=1
        if case%7==0:
            if log is original:coverage['blocked']+=1
            return 255
        return 0
    cb=Blocked(lambda ctx,fn,obj,reason:event(h.read,nw,native,fn,obj,reason));ops=Callbacks(None,cb);clock=Operations()
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x96510:frame['base']=sp-8;u.mem_write(sp-8,seed);return
        if at in [0x965cc,0x965da]:frame['result']=bytes(u.mem_read(frame['base'],8));return
        if at==0x96544:coverage['retire']+=1;return
        if at==0x965a5:coverage['reserved']+=1;return
        if at==0x965cf:coverage['failed']+=1;return
        reason=struct.unpack('<I',u.mem_read(sp+4,4))[0];v=event(u.mem_read,u.mem_write,original,at,u.reg_read(X.UC_X86_REG_ECX),reason)
        u.reg_write(X.UC_X86_REG_EAX,0xabcd0000|v);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+8)
    h.u.mem_write(target,b'\xc2\x04\x00')
    for at in [0x96510,0x965cc,0x965da,0x96544,0x965a5,0x965cf,target]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    reserve=h.lib.h2_network_stream_reserve;reserve.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Callbacks)]+[C.c_uint32]*3;reserve.restype=C.c_uint32
    size=h.lib.h2_network_stream_record_size;size.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;size.restype=None
    for case in range(1536):
        original.clear();native.clear();frame.clear();h.write(stream,rng.randbytes(0x980));h.write(stream,P(vt));h.write(vt+4,P(target));oldest=100;count=case%9;latest=oldest+count;done=oldest+min(count,case//9%9)
        for off,v in [(0x2c,8),(0x30,latest),(0x34,oldest),(0x38,8),(0x3c,case%8),(0x40,count),(0x44,done),(0x94c,(latest+[-129,-128,-127,0,127,0x7fffffff][case//3%6])&0xffffffff)]:h.write(stream+off,P(v))
        seed=rng.randbytes(8);h.write(scratch,seed);timestamp=rng.getrandbits(32)
        def run():
            value=reserve(h.memory,C.byref(clock),C.byref(ops),stream,timestamp,scratch)
            assert h.read(scratch,8)==frame['result'],case
            nw(scratch,seed);return value
        h.call('reserve',0x96510,dict(esi=stream),[timestamp],run,0xffffffff);assert original==native,case
        for off,v in [(0x2c,8),(0x30,108),(0x34,100),(0x3c,case%8),(0x40,8),(0x48,rng.getrandbits(32))]:h.write(stream+off,P(v))
        sequence=101+case%8;value=[0,1,1536,0xffffffff,0x80000000,rng.getrandbits(32)][case%6]
        h.call('record_size',0x96810,dict(ecx=stream,eax=sequence,edi=value),[],lambda:size(h.memory,stream,sequence,value))
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-stream-reserve-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_stream_reserve.c','include/halo2/network_stream_reserve.h','src/network_stream_events.c','include/halo2/network_stream_events.h','tests/network_stream_reserve_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Stream sequence reservation and byte accounting with actual forced retirement/queue/lookup callees. Full persistent memory, eight-byte original frame, EAX and callback snapshots. Capacity and distance failures, blocked virtual return, mutation, zero/wrapped sizes and retired-slot reuse. Valid mapped queues and existing records; no live stream or whole packet construction.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
