#!/usr/bin/env python3
"""Isolated session coordinator: engine callees controlled, not composed gameplay."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
Trace=C.CFUNCTYPE(None,C.c_uint32,C.c_uint32,C.c_uint32)
P=lambda v:struct.pack('<I',v&0xffffffff)
CALLEES={0x617c0:('eax',0),0x618d0:('eax',0),0x61910:('eax',0),0x5a520:('eax',0),0x61ac0:('stack',4),0x61e00:('eax',0),0x61ef0:('stack',4),0x62de0:('eax',0),0x5fda0:('esi',0),0x62ab0:('esi',0),0x62990:('esi',0),0x62240:('edi',0),0x62640:('ecx',0),0x627e0:('ecx',0)}
REGS={'eax':X.UC_X86_REG_EAX,'esi':X.UC_X86_REG_ESI,'edi':X.UC_X86_REG_EDI,'ecx':X.UC_X86_REG_ECX}
def suite(h):
    session=h.table;observer=session+0x8000;rng=random.Random(0x5a090)
    original=[];native=[];coverage={}
    states=[0,1,2,3,4,5,6,7,8,9,10,11,0xffffffff,0x80000000]
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def get(read,p):return struct.unpack('<I',read(p,4))[0]
    def event(read,write,events,at,s,peer):
        assert s==session,(hex(at),hex(s))
        events.append((at,s,peer,bytes(read(session,0x7800))))
        if events is original:coverage[hex(at)]=coverage.get(hex(at),0)+1
        mode=case//len(states)%6
        if mode==1 and len(events)==1:write(session+0x741c,P(states[case//84%len(states)]))
        if mode==2 and at==0x62de0:
            write(session+0x741c,P(states[case//84%len(states)]))
        if mode==3 and at==0x5fda0:
            write(session+0x54,P(peer+1 if case%2 else 4))
            write(session+0x741c,P(3))
        if mode==4 and at==0x62240:write(session+0x741c,P(states[case//84%len(states)]))
        if mode==5 and at==0x62ab0:write(session+0x741c,P(states[case//84%len(states)]))
        if mode==5 and at==0x62640:write(session+0x741c,P(0))
    cb=Trace(lambda at,s,p:event(h.read,nw,native,at,s,p))
    setter=h.lib.h2_test_session_update_trace;setter.argtypes=[Trace];setter(cb)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);reg,purge=CALLEES[at]
        s=get(u.mem_read,sp+4) if reg=='stack' else u.reg_read(REGS[reg])
        peer=u.reg_read(X.UC_X86_REG_EAX) if at==0x5fda0 else 0
        event(u.mem_read,u.mem_write,original,at,s,peer)
        u.reg_write(X.UC_X86_REG_EIP,get(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in CALLEES:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    # The coordinator forwards contexts; the controlled callees never dereference
    # their fields. Its one nested messages->clock load still needs valid backing.
    messages=C.create_string_buffer(256);control=C.create_string_buffer(256);observer_context=C.create_string_buffer(256)
    C.cast(control,C.POINTER(C.c_void_p))[0]=C.addressof(messages)
    scratch=(C.c_uint32*14)(*[session+0xa000+i*0x100 for i in range(14)])
    fn=h.lib.h2_network_session_update;fn.argtypes=[C.POINTER(Memory),C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint32,C.c_void_p];fn.restype=None
    for case in range(4096):
        original.clear();native.clear();h.write(session,rng.randbytes(0xa000))
        h.write(session+8,P(observer));h.write(session+0x741c,P(states[case%len(states)]))
        h.write(session+0x54,P([0,1,2,4,0xffffffff,0x80000000][case//14%6]));h.write(session+0x40,P(case%4))
        for i in range(4):
            h.write(session+0x72e0+i*20,P(i));h.write(session+0x72dd+i*20,bytes([0 if (case+i)%5==0 else 255]))
            h.write(observer+0xa8+i*0x528,P(1 if (case+i)%3 else 7))
        h.call('session_update_boundaries',0x5a090,dict(eax=session),[],lambda:fn(h.memory,control,observer_context,None,session,scratch),None)
        assert original==native,case
    assert set(coverage)=={hex(a) for a in CALLEES},coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_session_update_boundaries.so');p.add_argument('--report',default='analysis/network-session-update-boundaries-preview.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
    files=['src/network_session_update.c','include/halo2/network_session_update.h','tests/network_session_update_boundary_shim.c','tests/network_session_update_boundaries_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,total_comparisons=sum(h.counts.values()),coverage=coverage,source_hashes={f:sha(ROOT/f) for f in files},scope='Original coordinator instructions with all fourteen engine callees controlled equally on both sides. Full persistent memory, callee order/arguments/snapshots and state/count mutations. Does not validate composed callees, handoff math, live networking or gameplay.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
