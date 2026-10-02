#!/usr/bin/env python3
"""Peer attachment and insertion; original CRT wide-string copy stays intact."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_state_oracle import Operations,Ticks

def suite(h):
    rng=random.Random(0x5fbd0);session=h.table;identity=session+0x8000;extra=identity+64;iteration=0;selected=0
    original=[];native=[];coverage={}
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events):
        events.append(bytes(read(session,0x7900)))
        if iteration%3==0:
            write(session+0x54,pack(0x87654321));write(session+0x72dc+selected*20+4,pack(0x12345678));write(session+0x765c,b'\0')
        return (0xfffffff0+iteration)&0xffffffff
    cb=Ticks(lambda ctx:event(h.read,nw,native));clock=Operations();clock.ticks=cb
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);value=event(u.mem_read,u.mem_write,original);coverage['ticks']=coverage.get('ticks',0)+1
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    attach=h.lib.h2_network_session_attach_peer;attach.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*4;attach.restype=None
    add=h.lib.h2_network_session_add_peer;add.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*6;add.restype=None
    for mode in ['attach','add']:
        for iteration in range(512):
            h.write(session,rng.randbytes(0x7900));h.write(identity,rng.randbytes(80));original.clear();native.clear();selected=iteration%16
            peer=session+0x58+selected*0x10c;flag=[0,1,2,255][iteration//16%4];observer_index=[0xffffffff,0,1,15,0x80000000][iteration//64%5]
            h.write(session+0x54,pack([0,1,15,0xffffffff,0x7fffffff][iteration//7%5]));h.write(session+0x765c,bytes([0 if iteration%3==0 else 255]))
            h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack(0x13572468))
            source=[identity,peer,peer+4,peer-4,session+0x54][iteration//5%5]
            optional=[0,extra,peer+0xec,peer+0xf0,peer+0xf4,peer+0xfc][iteration//9%6]
            length=[0,1,14,15,16,30,31,32,39][iteration//17%9]
            h.write(0x450aac,b''.join(struct.pack('<H',0x8001+i) for i in range(length))+bytes(80-length*2))
            if mode=='attach':
                h.call(mode,0x5f900,dict(edx=session,ecx=selected,eax=flag),[observer_index],lambda:attach(h.memory,C.byref(clock),session,selected,flag,observer_index))
            else:
                h.call(mode,0x5fbd0,{},[session,selected,source,flag,observer_index,optional],lambda:add(h.memory,C.byref(clock),session,selected,source,flag,observer_index,optional))
            assert original==native,(mode,iteration)
    assert coverage.get('ticks')==512,coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-membership-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_session_membership.c','include/halo2/network_session_membership.h','tests/network_session_membership_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='peer attachment and insertion; actual attachment and original CRT wide-string copy, SDK ticks controlled. Full memory and callback snapshots, byte flags, wrapping counters, identity/extra aliases, synthetic default-name lengths and callback field mutations. Not full admission or gameplay.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
