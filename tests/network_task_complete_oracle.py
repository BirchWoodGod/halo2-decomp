#!/usr/bin/env python3
"""Task completion with actual scheduling and CRC; only object callbacks controlled."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STOP
from data_array_oracle import ROOT,Memory,EXPECTED
Invoke=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32)
class Callbacks(C.Structure):
    _fields_=[('context',C.c_void_p),('invoke',Invoke)]

def suite(h):
    rng=random.Random(0x81050);obj=h.table;data=obj+0x200;table=obj+0x400;alternate=table+0x40
    original=[];native=[];iteration=0
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    word=lambda v:struct.pack('<H',v&0xffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,function,object):
        events.append((function,object,bytes(read(obj,0x500)),bytes(read(0x4d8ba0,0x310)),bytes(read(0x55e700,4))))
        # Mutations force the caller to distinguish captured status from fresh fields.
        if iteration%3==0:
            write(object+4,word(0xa55a));write(object+12,word([0,1,2,3][iteration//3%4]))
            write(object+6,word([0,1,2,3][iteration//7%4]));write(object,pack(alternate))
            write(object+0x20,pack(99));write(object+10,word([0,1,2][iteration//11%3]))
            write(object+0x10,pack(0x13572468));write(0x55e700,pack(0xffffffff))
        if iteration%5==0:
            write(0x4d8c28,pack(0));write(0x4d8ba8,pack(0xffffffff));write(0x4d8be8,pack(0xffffffff))
        return [0,1,0x80,0xff][(iteration+(function-STOP)//0x10)%4]
    invoke=Invoke(lambda ctx,fn,obj:event(h.read,nw,native,fn,obj));ops=Callbacks(None,invoke)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);objarg=struct.unpack('<I',u.mem_read(sp+4,4))[0]
        result=event(u.mem_read,u.mem_write,original,at,objarg)
        u.reg_write(X.UC_X86_REG_EAX,0xaabbcc00|result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+8)
    for at in [STOP+0x800,STOP+0x810,STOP+0x820,STOP+0x830]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_task_complete;fn.argtypes=[C.POINTER(Memory),C.POINTER(Callbacks),C.c_uint32,C.c_uint32];fn.restype=None
    for iteration in range(1536):
        original.clear();native.clear();h.write(obj,rng.randbytes(0x500));h.write(0x4d8ba0,rng.randbytes(0x310))
        for i in range(32):h.write(0x4d8c28+i*20,pack(0 if i==iteration%34 else obj))
        for base in [0x4d8ba8,0x4d8be8]:
            for i in range(16):h.write(base+i*4,pack(0xffffffff if i==iteration//3%18 else i))
        h.write(obj,pack(table if iteration%7 else 0))
        status=rng.getrandbits(16);flags=iteration%8;kind=[0,1,2,3,0xffff][iteration//8%5]
        h.write(obj+4,struct.pack('<HHHH',status,flags,[0,1,2,4][iteration//40%4],kind))
        h.write(obj+0x24,struct.pack('<II',data,[0,1,4,63,128][iteration//13%5]))
        for t in [table,alternate]:
            for offset,at in [(0x10,STOP+0x800),(0x14,STOP+0x810),(0x18,STOP+0x820)]:
                h.write(t+offset,pack(0 if iteration//17%4==(offset-0x10)//4 else at if t==table else STOP+0x830))
        h.write(0x55e700,pack([0,1,0xffffffff][iteration//19%3]))
        reason=[0,1,6,7,13,0x10001,0xffffffff][iteration//5%7]
        try:h.call('task_complete',0x81050,dict(eax=obj,ecx=reason),[],lambda:fn(h.memory,C.byref(ops),obj,reason))
        except Exception:
            print('iteration',iteration,'reason',reason,'kind',kind,'flags',flags);raise
        assert original==native,(iteration,original,native)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-task-complete-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_tracking.c','include/halo2/network_tracking.h','src/crc.c','tests/network_task_complete_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original task completion with actual scheduling and CRC callees. Only object callbacks are controlled. Full memory, callback snapshots/arguments/order, status capture, reason and flag combinations, callback field/table mutations, retries and full tracking tables. Not complete networking shutdown or Linux networking.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
