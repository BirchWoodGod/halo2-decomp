#!/usr/bin/env python3
"""Tracked task scheduling against original instructions, including actual CRC."""
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x8e500)
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    obj=h.table;data=obj+0x100
    funcs={}
    for name,count in [('find_free',0),('queue_read',3),('queue_write',3)]:
        fn=getattr(h.lib,'h2_network_tracking_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*count;fn.restype=C.c_uint32;funcs[name]=fn
    for name in ['read','write']:
        fn=getattr(h.lib,'h2_network_task_start_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*6;fn.restype=C.c_uint8;funcs['start_'+name]=fn
    for mode in ['find_free','queue_read','queue_write','start_read','start_write']:
        for iteration in range(512):
            h.write(0x4d8ba0,rng.randbytes(0x310));h.write(obj,rng.randbytes(0x200))
            # Full tables retain the original sentinel-derived writes before the table.
            free=iteration%34
            for i in range(32):h.write(0x4d8c28+i*20,pack(0 if i==free or (iteration%7==0 and i>free) else obj))
            for base in [0x4d8ba8,0x4d8be8]:
                slot=(iteration//3)%18
                for i in range(16):h.write(base+i*4,pack(0xffffffff if i==slot or (iteration%5==0 and i>slot) else i))
            type_=[0,1,2,3,4,0xffff][iteration//5%6]
            status=[0,2,8,10,0xffff][iteration//7%5]
            pending=[0,0,0,1,2,0xffff][iteration//11%6]
            length=[0,1,3,4,5,16,63,128][iteration//13%8]
            target=data if iteration%4 else obj+0x10 # include CRC/data aliasing task fields
            h.write(obj+4,struct.pack('<HHHH',status,rng.getrandbits(16),type_,pending))
            h.write(obj+0x24,struct.pack('<II',target,length))
            if mode=='find_free':
                h.call(mode,0x8e1e0,{},[],lambda:funcs[mode](h.memory),0xffffffff)
            elif mode.startswith('queue_'):
                addr=0x8e580 if mode=='queue_read' else 0x8e500
                regs={} if mode=='queue_read' else dict(eax=length)
                args=[obj,target,length] if mode=='queue_read' else [obj,target]
                h.call(mode,addr,regs,args,lambda:funcs[mode](h.memory,obj,target,length),0xffffffff)
            else:
                token,a,b,c=[rng.getrandbits(32) for _ in range(4)];flags=rng.getrandbits(32)
                h.call(mode,0x80f70 if mode=='start_read' else 0x80ff0,dict(eax=token,esi=obj),[a,b,c,flags],lambda:funcs[mode](h.memory,obj,token,a,b,c,flags),255)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-tracking-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_tracking.c','include/halo2/network_tracking.h','src/crc.c','tests/network_tracking_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Five task scheduling routines, actual original CRC and callees, no intercepted dependencies. Full mapped-memory and return comparisons; occupied/free/full tables, all task types, pending work, flag combinations, CRC lengths and aliasing task fields. Does not establish task completion, cancellation, or Linux networking.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
