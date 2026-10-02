#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider

def suite(h):
    rng=random.Random(0xb2fc0);reply=h.table;cache=reply+0x1000;other=reply+0x4000;original=[];native=[];iteration=0;now=0
    def nw(p,data):C.memmove(h.pointer+p-BASE,data,len(data))
    def tick(read,write,events):
        events.append((bytes(read(cache,0x784*4)),bytes(read(0x4d8eb4,24))))
        if iteration%3==0:
            write(0x4d8ec8,struct.pack('<I',other));write(0x4d8ec4,bytes(4));write(0x4d8eb5,b'\0')
            for i in range(4):write(cache+i*0x784+0x44,b'\xff')
        return now
    callback=Ticks(lambda ctx:tick(h.read,nw,native));ops=Operations(None,callback,Provider())
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);answer=tick(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,answer);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    store=h.lib.h2_discovery_store_reply;store.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];store.restype=None
    handle=h.lib.h2_message_handle_broadcast_reply;handle.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32,C.c_uint32];handle.restype=None
    for wrapper in [False,True]:
        for iteration in range(384):
            original.clear();native.clear();h.write(reply,rng.randbytes(0x800));h.write(cache,rng.randbytes(0x784*4));h.write(other,rng.randbytes(0x784*4))
            h.write(0x4d8eb4,bytes([0 if iteration%17==0 else 255,iteration%2]));h.write(0x4d8ec4,struct.pack('<II',[4,4,4,1,0,0xffffffff][iteration//6%6],cache))
            nonce=rng.randbytes(8);h.write(0x4d8ebc,nonce);h.write(reply+4,nonce)
            h.write(reply,struct.pack('<H',2 if iteration%7 else 3))
            if iteration%11==0:h.write(reply+8,struct.pack('<I',h.u32(reply+8)^1))
            rank=[0,1,5,0x7fff,0x8000,0xffff][iteration//2%6]
            h.write(reply+0xaa,struct.pack('<H',rank));h.write(reply+0x20,struct.pack('<H',1 if iteration%13==0 else 0))
            mode=iteration%6
            for i in range(4):
                entry=cache+i*0x784
                h.write(entry,bytes([0 if mode==0 or (mode==2 and i==0) else 255]))
                h.write(entry+0x10e,struct.pack('<H',0 if mode==4 else 10+i))
                if (mode==2 and i==2) or (mode==3 and i in [1,3]):h.write(entry+0xe0,h.read(reply+0x7c,36))
            if mode==5:h.write(cache+0x70,h.read(reply+12,0x714))
            if iteration%23==0:
                h.write(reply+12,bytes(0x714));h.write(cache,bytes(0x784*4))
            override=iteration%2;now=[0,1,0x7fffffff,0xfffffffe,0xffffffff][iteration%5]
            h.write(0x510548,bytes([override]));h.write(0x51054c,struct.pack('<I',now))
            if wrapper:h.call('broadcast_reply_handler',0x940b0,dict(eax=reply),[reply+0x740],lambda:handle(h.memory,C.byref(ops),reply,reply+0x740))
            else:h.call('discovery_store_reply',0xb2fc0,{},[reply],lambda:store(h.memory,C.byref(ops),reply))
            assert original==native,(wrapper,iteration)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/discovery-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/discovery.c','include/halo2/discovery.h','include/halo2/network_state.h','tests/discovery_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original cache updater and broadcast-reply handler intact; only SDK clock controlled. Full guest memory and clock snapshots, disabled search, query mismatch, signed counts/ranks, first free/matching slot, duplicate matches, last replacement, unchanged descriptions, dirty flags, zero inserts, clock override and callback mutation. Disjoint reply/cache. No live discovery or game startup.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
