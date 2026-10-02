#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
Format=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class Platform(C.Structure):
    _fields_=[('context',C.c_void_p),('format',Format)]

def suite(h):
    rng=random.Random(0x11c9c0);buffer=h.table+32;fmt=buffer+0x100;arguments=fmt+0x100;original=[];native=[];iteration=0
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,destination,limit,format_address,args):
        events.append((destination,limit,format_address,bytes(read(args,24)),bytes(read(buffer-16,96))))
        # Explicit CRT boundary: arbitrary writes/returns verify wrapper behavior,
        # including no-write failures and forced termination after the call.
        if iteration%4:
            n=min(limit,7);write(destination,bytes((iteration+k)%256 for k in range(n)))
        write((buffer+capacity-1)&0xffffffff,b'\x7f')
        return [0,1,0xffffffff,0x80000000][iteration%4]
    cb=Format(lambda ctx,d,n,f,a:event(h.read,nw,native,d,n,f,a));ops=Platform(None,cb)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at in [0x11c9de,0x11ca1e]:
            # Model cdecl caller cleanup for the harness's callee-purge contract.
            u.mem_write(sp+28,bytes(u.mem_read(sp,4)));u.reg_write(X.UC_X86_REG_ESP,sp+28);return
        args=struct.unpack('<4I',u.mem_read(sp+4,16));value=event(u.mem_read,u.mem_write,original,*args)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4)
    for at in [0x321980,0x11c9de,0x11ca1e]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    for mode,address in [('format',0x11c9c0),('append_format',0x11c9e0)]:
        fn=getattr(h.lib,'h2_text_'+mode);fn.argtypes=[C.POINTER(Memory),C.POINTER(Platform)]+[C.c_uint32]*4;fn.restype=C.c_uint32
        for iteration in range(512):
            original.clear();native.clear();h.write(buffer-16,rng.randbytes(96));length=[0,1,7,17][iteration%4];h.write(buffer,b'X'*length+b'\0');capacity=[0,1,8,32,0xffffffff][iteration//4%5]
            h.write(fmt,b'%hd %02X %s\0');values=[rng.getrandbits(32) for _ in range(6)];h.write(arguments,struct.pack('<6I',*values))
            regs=dict(esi=buffer,edi=capacity) if mode=='format' else dict(ebx=buffer,eax=capacity)
            h.call(mode,address,regs,[fmt,*values],lambda:fn(h.memory,C.byref(ops),buffer,capacity,fmt,arguments),0xffffffff)
            assert original==native,(mode,iteration)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/text-format-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/text_format.c','include/halo2/text_format.h','tests/text_format_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Two formatting wrappers only. Actual original instructions, full memory and return, guest varargs bytes/call order, append scan and wrapping capacities, forced termination after arbitrary formatter returns/writes. CRT321980 controlled boundary; format-specifier interpretation not implemented or validated here.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
