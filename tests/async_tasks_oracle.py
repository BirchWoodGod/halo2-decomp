#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,itertools,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from online_poll_oracle import Call
from data_array_oracle import ROOT,Memory,EXPECTED
class Ops(C.Structure):
    _fields_=[('context',C.c_void_p),('release',Call)]
def suite(h):
    rng=random.Random(0x7b650);a=h.table;b=a+0x100;task=a+0x900
    original=[];native=[];result=0;mutate=False
    def event(read,write,events,value):
        events.append((value,bytes(read(a,0x800))))
        if mutate:write(0x4cf8d8,struct.pack('<I',b))
        return result
    callback=Call(lambda ctx,value:event(h.read,lambda p,d:C.memmove(h.pointer+p-BASE,d,len(d)),native,value))
    ops=Ops(None,callback)
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        value=event(u.mem_read,u.mem_write,original,struct.unpack('<I',u.mem_read(esp+4,4))[0])
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3cd172,end=0x3cd172)
    release=h.lib.h2_async_task_release;release.argtypes=[C.POINTER(Memory),C.POINTER(Ops),C.c_uint32];release.restype=None
    idle=h.lib.h2_async_task_is_idle;idle.argtypes=[C.POINTER(Memory),C.c_uint32];idle.restype=C.c_uint8
    def setup(enabled,limit,salt,poison):
        h.write(a,rng.randbytes(0xa00))
        for pool,entries,bitmap in [(a,a+0x400,a+0x300),(b,a+0x600,a+0x304)]:
            for off,v in [(0x20,3),(0x24,12),(0x34,3),(0x38,limit),(0x3c,3),(0x44,entries),(0x48,bitmap)]:h.write(pool+off,struct.pack('<I',v))
            h.write(pool+0x2a,bytes([8 if poison else 0]));h.write(bitmap,struct.pack('<I',7))
            for i in range(3):h.write(entries+12*i,struct.pack('<HHII',salt if i==1 else 0x8001,0,task,0))
        h.write(0x4cf8d4,bytes([enabled]));h.write(0x4cf8d8,struct.pack('<I',a));original.clear();native.clear()
    cases=[(0,3,0x8002,0x80020001),(1,0,0x8002,0x80020001),(1,0xffffffff,0x8002,0x80020001),(1,3,0,0x80020001),(1,3,0x8003,0x80020001),(1,3,0x8002,0xffffffff),(1,3,0x8002,0x80020003),(1,3,0x8002,0x80020001),(255,3,0x7fff,0x7fff0001)]
    for (enabled,limit,salt,handle),result,mutate,poison in itertools.product(cases,[0,1,0x80004005],[False,True],[False,True]):
        setup(enabled,limit,salt,poison)
        h.call('release',0x7b650,dict(edi=handle),[],lambda:release(h.memory,C.byref(ops),handle))
        assert native==original
    for (enabled,limit,salt,handle),status in itertools.product(cases,[0,1,0xffffffff]):
        setup(enabled,limit,salt,False);h.write(task+4,struct.pack('<I',status))
        h.call('idle',0x7b6c0,dict(eax=handle),[],lambda:idle(h.memory,handle),mask=255)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/async-task-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/async_tasks.c','include/halo2/async_tasks.h','src/data_array.c','tests/async_tasks_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original release and idle instructions; SDK release controlled, original data deletion intact. Full memory, AL for idle, callback snapshots, pool replacement, invalid handles, SDK errors and poisoning. No actual SDK service execution.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
