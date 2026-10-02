#!/usr/bin/env python3
"""Original-instruction comparisons for connection timer and stream initialization."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0x95cf0);object_address=h.table;iteration=0;original=[];native=[];coverage={'ticks':0,'override_switch':0}
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def tick_event(read,write,events):
        events.append((bytes(read(object_address,0x97c)),bytes(read(0x4e6398,8)),bytes(read(0x4cf6e8,4))))
        if events is original:coverage['ticks']+=1
        # SDK callbacks can change configuration and later clock selection.
        write(0x4e6398,pack(iteration+len(events)));write(0x4e639c,pack(0xffffffff-len(events)))
        write(0x4cf6e8,pack([0,1,1000,0xffffffff,0x80000000][iteration%5]))
        write(0x4cf70c,b''.join(pack(iteration+k+len(events)) for k in range(4)))
        write(object_address+0x30,pack(0xabcdef01))
        if iteration%3==0:
            write(0x510548,b'\1');write(0x51054c,pack(iteration*17))
            if events is original:coverage['override_switch']+=1
        return (0xfffffff0+iteration*1001+len(events))&0xffffffff
    tick=Ticks(lambda ctx:tick_event(h.read,nw,native));clock=Operations(None,tick,Provider())
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);value=tick_event(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    for name,address,register in [('connection_reset_timers',0x88d20,'eax'),('stream_reset',0x95cf0,'esi')]:
        fn=getattr(h.lib,'h2_network_'+name);fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];fn.restype=None
        for iteration in range(512):
            original.clear();native.clear();h.write(object_address,rng.randbytes(0x97c))
            h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack([0,1,999,1000,0xffffffff,0x80000000,rng.getrandbits(32)][iteration//2%7]))
            h.write(0x4cf6e8,pack([0,1,1000,0xffffffff,0x80000000,rng.getrandbits(32)][iteration//14%6]))
            h.write(0x4cf70c,rng.randbytes(16));h.write(0x4e6398,rng.randbytes(8))
            h.call(name,address,{register:object_address},[],lambda:fn(h.memory,C.byref(clock),object_address))
            assert original==native,(name,iteration)
            if iteration%2:assert not original
            elif name=='connection_reset_timers':assert len(original)==(1 if iteration%3==0 else 6)
            else:assert len(original)==1
    assert coverage['ticks'] and coverage['override_switch']
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-setup-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_connection_setup.c','include/halo2/network_connection_setup.h','tests/network_connection_setup_oracle.py','tests/network_state_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),boundary_coverage=coverage,comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Connection timer reset and stream initialization; original instructions, full guest memory, callback state/order, clock override changes and wrapped sequence arithmetic. SDK clock controlled; not connection opening or gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
