#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,itertools,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from online_poll_oracle import Operations,Call
from data_array_oracle import ROOT,Memory,EXPECTED
class CancelOps(Operations):
    _fields_=[('prepare_cancel',Call),('close_task',Call),('cancel_kind33',Call)]
def suite(h):
    lib=h.lib;rng=random.Random(0x6b640);a=h.table;b=a+0x100;elements=a+0x400;task=elements+20
    original=[];native=[];sequence=[0x1500f2];prepare=0;mutate=False
    def nw(p,data):C.memmove(h.pointer+p-BASE,data,len(data))
    def event(read,write,events,kind,handle):
        events.append((kind,handle,bytes(read(a,0x180)),bytes(read(elements,60))))
        if mutate:
            if kind=='close':write(0x4cf78c,struct.pack('<I',b))
            else:write(task+12,struct.pack('<I',0x5678))
        if kind=='status':return 0x1510f0
        if kind=='prepare':return prepare
        if kind=='continue':return sequence[min(sum(e[0]=='continue' for e in events)-1,len(sequence)-1)]
        return 0x80004005
    callbacks={name:Call(lambda ctx,handle,name=name:event(h.read,nw,native,name,handle))
               for name in ['status','continue','prepare','close','kind33']}
    ops=CancelOps()
    for field,name in [('login_status','status'),('continue_task','continue'),('prepare_cancel','prepare'),('close_task','close'),('cancel_kind33','kind33')]:setattr(ops,field,callbacks[name])
    addresses={0x3a0650:'status',0x3a0620:'continue',0x3a07b9:'prepare',0x3a062b:'close',0x3a6969:'kind33'}
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);handle=struct.unpack('<I',u.mem_read(esp+4,4))[0]
        value=event(u.mem_read,u.mem_write,original,addresses[address],handle)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for address in addresses:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    for name in ['cancel','cancel_kind33']:
        fn=getattr(lib,'h2_online_task_'+name);fn.argtypes=[C.POINTER(Memory),C.POINTER(CancelOps),C.c_uint32];fn.restype=None
    def setup(kind,sdk,poison=False):
        h.write(a,rng.randbytes(0x800))
        for array,entry,bitmap in [(a,elements,a+0x300),(b,a+0x600,a+0x304)]:
            for off,value in [(0x20,3),(0x24,20),(0x34,3),(0x38,3),(0x3c,3),(0x44,entry),(0x48,bitmap)]:h.write(array+off,struct.pack('<I',value))
            h.write(array+0x2a,bytes([8 if poison else 0]));h.write(bitmap,struct.pack('<I',7))
            for i in range(3):h.write(entry+i*20,struct.pack('<HHIIII',0x8001+i,0,kind if i==1 else 1,0,sdk if i==1 else 0x1234,1))
        h.write(0x4cf78c,struct.pack('<I',a));h.write(0x467214,struct.pack('<II',0x80010000,77));h.write(0x4d8b18,b'\1\1')
        original.clear();native.clear()
    for kind,sdk,mode,prepare,mutate,poison in itertools.product([0,2,3,33,99],[0,0xffffffff,0x1234],range(3),[0,0x80004005],[False,True],[False,True]):
        sequence=[[0x1500f2],[0,1,0x1500f2],[0,0x80004005]][mode]
        setup(kind,sdk,poison)
        h.call('cancel',0x6b640,dict(edi=0x80020001),[],lambda:lib.h2_online_task_cancel(h.memory,C.byref(ops),0x80020001))
        assert original==native
        array=b if mutate and sdk not in [0,0xffffffff] else a
        assert h.u32(array+0x3c)==2 and h.u32(h.u32(array+0x48))==5
    for handle,login_handle,status,mutate in itertools.product([0xffffffff,0x12340001,0x80020001],[0xffffffff,0x80010000],[0,1,5],[False,True]):
        setup(33,0x1234);h.write(0x467214,struct.pack('<I',login_handle));h.write(elements+16,struct.pack('<I',status))
        h.call('kind33',0x8c550,dict(edx=handle),[],lambda:lib.h2_online_task_cancel_kind33(h.memory,C.byref(ops),handle))
        assert original==native
        assert len(native)==int(handle==0x80020001 and login_handle!=0xffffffff and status==1)
    for handle in [0xffffffff,0x12340001,0x80020003]:
        setup(2,0x1234)
        h.call('cancel_invalid',0x6b640,dict(edi=handle),[],lambda:lib.h2_online_task_cancel(h.memory,C.byref(ops),handle))
        assert not original and not native

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/online-cancel-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/online_tasks.c','src/data_array.c','src/transport.c','tests/online_cancel_oracle.py','tests/online_poll_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Cancellation and kind-33 helper; all original engine callees intact, SDK calls controlled. Full memory and callback snapshots; completion/error sequences, changed pool pointers, poisoned deletion and invalid handles. No full shutdown or online SDK backend.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
