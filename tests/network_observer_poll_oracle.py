#!/usr/bin/env python3
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT, Memory, EXPECTED
from network_state_oracle import Operations, Ticks, Provider

Query=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
class Queries(C.Structure):
    _fields_=[('context',C.c_void_p),('query',Query)]

def suite(h):
    rng=random.Random(0x77940);observer=h.table;config=observer+0x6000
    connection=config+0x300;objects=config+0x500
    original=[];native=[];coverage={'ticks':0,'query':0,'accepted':0}
    def write(a,b):C.memmove(h.pointer+a-BASE,b,len(b))
    def event(read,put,out,kind,args):
        out.append((kind,args,bytes(read(entry,0x20))))
        if kind=='ticks':
            if mutate:
                put(observer+16,struct.pack('<I',config+0x100))
                put(connection+0xa8,struct.pack('<I',now))
                put(connection+0x54,struct.pack('<I',0))
            return now
        function,obj,which=args
        i=(obj-objects)//16
        if mutate:
            put(entry+9,bytes([masks[i]]))
            # Replace the next consumer's virtual target during iteration.
            if i<3:put(objects+(i+1)*16+8,struct.pack('<I',0x3000610))
        return answers[i]
    ticks=Ticks(lambda ctx:event(h.read,write,native,'ticks',()))
    provider=Provider(lambda *args:0)
    clock=Operations(None,ticks,provider)
    query=Query(lambda ctx,f,o,i:event(h.read,write,native,'query',(f,o,i)))
    ops=Queries(None,query)
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);is_tick=address==0x3314b0
        args=() if is_tick else (address,u.reg_read(X.UC_X86_REG_ECX),struct.unpack('<I',u.mem_read(esp+4,4))[0])
        result=event(u.mem_read,u.mem_write,original,'ticks' if is_tick else 'query',args)
        u.reg_write(X.UC_X86_REG_EAX,result)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0])
        u.reg_write(X.UC_X86_REG_ESP,esp+4+(0 if is_tick else 4))
    for a in [0x3314b0,0x3000600,0x3000610]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=a,end=a)
    fn=h.lib.h2_network_observer_poll_consumers
    fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Queries),C.c_uint32,C.c_uint32]
    fn.restype=C.c_uint8
    for case in range(1536):
        h.write(observer,rng.randbytes(0x6800));index=case%15
        entry=observer+0xa8+index*0x528;mutate=bool(case%2)
        now=rng.choice([0,1,0xffffffff,0x7fffffff,0x80000000,rng.getrandbits(32)])
        previous=rng.choice([0,now,(now-100)&0xffffffff,rng.getrandbits(32)])
        h.write(0x4d87d4,struct.pack('<I',connection))
        h.write(entry+12,struct.pack('<I',0xffffffff if case%11==0 else 0))
        h.write(connection+0x54,struct.pack('<I',[0,3,4,5,6,0xffffffff,0x80000000,0x7fffffff][case%8]))
        h.write(connection+0xa8,struct.pack('<I',previous))
        h.write(observer+16,struct.pack('<I',config))
        for p in [config,config+0x100]:h.write(p+0x70,struct.pack('<I',rng.choice([0,1,99,100,101,0xffffffff,0x80000000,0x7fffffff])))
        h.write(0x510548,bytes([0 if case%3 else 255]));h.write(0x51054c,struct.pack('<I',now))
        h.write(entry+9,bytes([case%256]))
        masks=[rng.randrange(256) for _ in range(4)]
        answers=[rng.choice([0,0,0,1,255]) for _ in range(4)]
        for i in range(4):
            obj=objects+i*16;h.write(observer+0x14+i*36,struct.pack('<I',obj))
            h.write(obj,struct.pack('<I',obj+8));h.write(obj+8,struct.pack('<I',0x3000600))
        original.clear();native.clear()
        result=h.call('poll-consumers',0x77940,dict(eax=observer,ebx=index),[],
            lambda:fn(h.memory,C.byref(clock),C.byref(ops),observer,index),mask=255)
        assert original==native,(case,original,native)
        for e in original:coverage[e[0]]+=1
        coverage['accepted']+=result
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/network-observer-poll-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_poll.c','include/halo2/network_observer_poll.h','tests/network_observer_poll_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),coverage=coverage,
        source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original consumer-poll instructions, AL and full memory; signed connection state and elapsed thresholds, wrapping clocks, override clock, callback mask and virtual target mutation, config reload after SDK tick. Clock and consumer callbacks controlled.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
