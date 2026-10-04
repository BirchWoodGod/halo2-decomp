#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from network_state_oracle import Operations,Ticks
from engine_pools_oracle import BASE
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    f=h.lib.h2_network_session_remove_handoff_candidate;f.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];f.restype=None
    rng=random.Random(0x61390);session=h.table;original=[];native=[];case=0
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def event(read,write,events):
        events.append(bytes(read(session,0x7900)))
        write(session+0x742c,P(7));write(session+0x7424,P(0x12345678))
        write(session+0x741c,P(10));write(session+0x7420,P(0xaabbccdd))
        return (0xfffffff0+case)&0xffffffff
    cb=Ticks(lambda ctx:event(h.read,nw,native));ops=Operations();ops.ticks=cb
    def hook(u,addr,size,ctx):
        result=event(u.mem_read,u.mem_write,original);sp=u.reg_read(X.UC_X86_REG_ESP)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    coverage={'ticks':0,'no_ticks':0,'selected':0,'other':0}
    peers=[0,1,15,31,32,63,255,256,0xffffffff,0x80000000]
    for case in range(1024):
        session=h.table+case%4;peer=peers[case%len(peers)];selected=case%3!=0
        h.write(session,rng.randbytes(0x7900));h.write(session+0x742c,P(peer if selected else peer+1))
        h.write(0x510548,P([0,1,255][case//3%3])+P(rng.getrandbits(32)))
        original.clear();native.clear()
        h.call('remove_handoff_candidate',0x61950,dict(esi=session,ecx=peer),[],lambda:f(h.memory,C.byref(ops),session,peer))
        assert original==native,(case,'callback state')
        coverage['ticks' if original else 'no_ticks']+=1;coverage['selected' if selected else 'other']+=1

    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-handoff-remove-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['tests/network_state_oracle.py','src/network_session_handoff_remove.c','include/halo2/network_session_handoff_remove.h','tests/network_session_handoff_remove_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),engine_library_sha256=H(library.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Handoff candidate removal with original instructions, full memory, stack purge and SDK clock snapshots. Selected/other peers, masked wide indexes, cached clock, callback mutation and unaligned sessions. No handoff controller or live networking.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
