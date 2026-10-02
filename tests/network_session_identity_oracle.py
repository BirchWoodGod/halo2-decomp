#!/usr/bin/env python3
"""Admission identity helpers: actual lookup callee and controlled SDK ticks."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks

def suite(h):
    rng=random.Random(0x62eb0);session=h.table;identity=session+0x8000;owner=identity+32;scratch=identity+64
    original=[];native=[];coverage={};iteration=0;selected=0;frame=0;seed=bytes(6);source_owner=owner
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def ticks(read,write,events):
        events.append(bytes(read(session,0x7900))+bytes(read(identity,64)))
        if iteration%3==0:
            write(source_owner+4,pack(0x87654321));write(session+0x111c,pack(0xffff))
            write(session+0x1120,bytes(read(session+0x7668+selected*36+10,12)))
        if iteration%7==0:write(session+0x741c,pack(0))
        return (0xfffffff0+iteration)&0xffffffff
    cb=Ticks(lambda ctx:ticks(h.read,nw,native));clock=Operations();clock.ticks=cb
    def hook(u,at,size,ctx):
        nonlocal frame
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x5f6f0:frame=sp-8;u.mem_write(frame,seed);return
        value=ticks(u.mem_read,u.mem_write,original);coverage['ticks']=coverage.get('ticks',0)+1
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x5f6f0,0x3314b0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    machine=h.lib.h2_network_session_find_machine;machine.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;machine.restype=C.c_uint32
    player=h.lib.h2_network_session_find_player;player.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*2;player.restype=C.c_uint32
    queue=h.lib.h2_network_session_queue_identity;queue.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*5;queue.restype=C.c_uint8
    for mode in ['machine','player','queue']:
        for iteration in range(512):
            h.write(session,rng.randbytes(0x7900));h.write(identity,rng.randbytes(64));seed=rng.randbytes(6);h.write(scratch,seed);original.clear();native.clear()
            h.write(session+0x741c,pack(0 if iteration%13==0 else 5));h.write(session+0x4c,pack(0xffffffff if iteration%17==0 else 123))
            h.write(session+0x54,pack([0,1,3,16,0xffffffff,0x80000000][iteration//16%6]));h.write(session+0x111c,pack(rng.getrandbits(32)))
            selected=iteration%17;entry=session+0x7668+selected*36
            for i in range(16):h.write(session+0x7668+i*36,bytes([0 if i==selected else 255]))
            source_identity=identity;source_owner=owner
            if mode=='machine':
                target=iteration%16;h.write(identity,h.read(session+0x62+target*0x10c,6))
                if iteration%4==0:h.write(session+0x62,h.read(identity,6))
                if iteration%5==0:h.write(identity+iteration%6,b'\0')
                if iteration%7==0:source_identity=session+0x62+target*0x10c
            else:
                target=iteration%16;h.write(identity,h.read(session+0x1120+target*0x13c,12))
                if iteration%4==0:h.write(session+0x1120,h.read(identity,12))
                if iteration%5==0:h.write(identity+iteration%12,b'\0')
                if mode=='queue' and selected<16:
                    if iteration%4==0:source_identity=entry+[6,10,14][iteration//4%3]
                    if iteration%6==0:source_owner=entry+[2,6,12][iteration//6%3]
            h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack(0x12345678))
            value=rng.getrandbits(32);argument=rng.getrandbits(32)
            def run():
                if mode=='machine':
                    result=machine(h.memory,session,source_identity,scratch)
                    assert h.read(scratch,6)==bytes(h.u.mem_read(frame,6)),(mode,iteration,'scratch');nw(scratch,seed);return result
                if mode=='player':return player(h.memory,session,source_identity)
                return queue(h.memory,C.byref(clock),session,source_identity,source_owner,value,argument)
            address={'machine':0x5f6f0,'player':0x5f890,'queue':0x62eb0}[mode]
            regs=dict(ecx=session) if mode!='queue' else dict(edx=source_identity,ebx=source_owner)
            args=[source_identity] if mode!='queue' else [session,value,argument]
            h.call(mode,address,regs,args,run,255 if mode=='queue' else 0xffffffff)
            assert original==native,(mode,iteration,'clock snapshot')
    assert coverage.get('ticks',0)>0
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-identity-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_session_identity.c','include/halo2/network_session_identity.h','tests/network_session_identity_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='six-byte machine lookup, twelve-byte player lookup, queued identity insertion with actual player lookup. Full memory/returns, machine local scratch, signed counts, masks, duplicates, full slots, input/output aliases and SDK clock mutation. No full admission or gameplay.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
