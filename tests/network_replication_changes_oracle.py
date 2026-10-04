#!/usr/bin/env python3
"""Execute original change-mask marking and flush instructions against native C."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
Filter=C.CFUNCTYPE(C.c_uint8,C.c_void_p,*([C.c_uint32]*6))
class Callbacks(C.Structure):_fields_=[('context',C.c_void_p),('filter',Filter)]
P=lambda n:struct.pack('<I',n&0xffffffff)
W=lambda n:struct.pack('<H',n&0xffff)
def suite(h):
    rng=random.Random(0x89710);base=h.table;manager=base;peers=[base+0x1000+i*0x6000 for i in range(6)];flags=base+0x26000;table=base+0x30000;registry=base+0x39040;objects=base+0x39400;vtable=base+0x39500;scratch=base+0x39600;other=base+0x39700;target=0x3000e00
    coverage=dict(increments=0,marks=0,filters=0,flush_marks=0,callback_mutations=0,signed_type=0,zero_mask=0,duplicate_peers=0)
    sites={0x8975b:'increments',0x897a6:'increments',0x897f2:'increments',0x8983e:'increments',0x8988a:'increments',0x8976a:'marks',0x897b5:'marks',0x89801:'marks',0x8984d:'marks',0x89899:'marks',0x8a0ef:'flush_marks'}
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    original=[];native=[]
    def event(read,write,log,fn,obj,record,mask,a,b):
        value=u32(read,mask);index=(record-table-0x14)//32
        log.append((fn,obj,record,value,a,b,bytes(read(table,0x8014)),bytes(read(manager,64)),bytes(read(other,64))))
        if log is original:coverage['filters']+=1
        mode=(case+index)%5
        write(mask,P(0 if mode==0 else value^(1<<((case+index)&31))))
        if mode==2:
            write(record,P(0xf0000000|((index+1)&1023)));write(table+12,P(other))
            if index<1023:write(record+32+12,P(0x80000000));write(record+32,P(0x80000000|((index+1)&1023)))
            if log is original:coverage['callback_mutations']+=1
        if mode==3:write(record+12,P(0xdeadbeef))
        return [0,1,255][(case+index)%3]
    cb=Filter(lambda ctx,fn,obj,record,mask,a,b:event(h.read,nw,native,fn,obj,record,mask,a,b));ops=Callbacks(None,cb)
    def hook(u,at,size,ctx):
        if at in sites:coverage[sites[at]]+=1;return
        sp=u.reg_read(X.UC_X86_REG_ESP);record,mask,a,b=struct.unpack('<IIII',u.mem_read(sp+4,16));obj=u.reg_read(X.UC_X86_REG_ECX)
        value=event(u.mem_read,u.mem_write,original,at,obj,record,mask,a,b)
        u.reg_write(X.UC_X86_REG_EAX,0xbeef0000|value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+20)
    h.u.mem_write(target,b'\xc2\x10\x00')
    for at in [target,*sites]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    mark=h.lib.h2_network_replication_mark_changes;mark.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;mark.restype=None
    flush=h.lib.h2_network_replication_flush_changes;flush.argtypes=[C.POINTER(Memory),C.POINTER(Callbacks),C.c_uint32,C.c_uint32];flush.restype=None
    for p in peers:h.write(p,bytes(0x5040));h.write(p+0x14,P(flags))
    h.write(flags,bytes(0x2050))
    for case in range(1024):
        index=[0,1,1023,rng.randrange(1024)][case%4];handle=(rng.getrandbits(22)<<10)|index;mask=[0,1,0xffffffff,rng.getrandbits(32)][case%4]
        if mask==0:coverage['zero_mask']+=1
        for j,p in enumerate(peers):
            h.write(p+12,P([0,15,16,31,32,255,0xffffffff][(case+j)%7]));h.write(p+0x5034,P([0,0xffffffff,0x7fffffff][(case+j)%3]));h.write(p+0x2c+index*20,W([0,3,3,0xffff][(case+j)%4]));h.write(p+0x28+index*20,P(0 if (case+j)%3 else rng.getrandbits(32)))
        h.write(flags+0x46+index*8,W([0,0xffff,1,0x8000,rng.getrandbits(16)][case%5]))
        for j in range(15):h.write(manager+4+j*4,P(0 if (case+j)%5==0 else peers[(j+case)%6]))
        coverage['duplicate_peers']+=1
        h.call('mark_changes',0x89710,dict(eax=manager,edi=handle),[mask],lambda:mark(h.memory,manager,handle,mask))
    for case in range(256):
        original.clear();native.clear();h.write(table,bytes(0x8014));h.write(table+12,P(manager));h.write(table+16,P(registry));h.write(vtable+0x50,P(target));h.write(scratch,rng.randbytes(4));saved=h.read(scratch,4)
        for j,p in enumerate(peers):
            records=bytearray(0x5040)
            for index in range(1024):struct.pack_into('<H',records,0x2c+index*20,3)
            struct.pack_into('<I',records,12,j);struct.pack_into('<I',records,0x14,flags);struct.pack_into('<I',records,0x5034,0xffffffff if case%2 else 0);h.write(p,bytes(records))
        h.write(flags,bytes([0xff if case%4==0 else 0])*0x2050)
        for j in range(15):h.write(manager+4+j*4,P(peers[j%6] if j%4 else 0));h.write(other+4+j*4,P(peers[(j+1)%6] if j%3 else 0))
        for k,kind in enumerate([-2,-1,0,3]):
            obj=objects+k*4;h.write(obj,P(vtable));h.write(registry+4+kind*4,P(obj))
        selected={0,1,2,1022,1023,*[rng.randrange(1024) for _ in range(16)]}
        for index in range(1024):
            record=table+0x14+index*32;h.write(record,P(0xffffffff))
            if index not in selected:continue
            kind=[-2,-1,0,3][(case+index)%4]
            if kind<0:coverage['signed_type']+=1
            h.write(record,P(0xffffffff if (case+index)%7==0 else (0xa0000000|index)));h.write(record+4,W(kind));h.write(record+6,bytes([0 if (case+index)%4==0 else 255]));h.write(record+12,P(0 if (case+index)%6==0 else rng.getrandbits(32)));h.write(record+24,P(rng.getrandbits(32)));h.write(record+28,P(rng.getrandbits(32)))
        def run():flush(h.memory,C.byref(ops),table,scratch);nw(scratch,saved)
        h.call('flush_changes',0x8a090,{},[table],run);assert original==native,case
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-replication-changes-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_replication_changes.c','include/halo2/network_replication_changes.h','tests/network_replication_changes_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Full persistent memory comparison for fifteen-peer mask propagation and 1024-record flush. Masked handles, masked x86 shifts, counter wrap, zero masks, repeated peer pointers, signed type indexing and callback order/mutation. Flush uses the actual recovered propagation callee; virtual implementation controlled. Four-byte replacement stack scratch excluded. Does not establish live replication, parent network frame or gameplay.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
