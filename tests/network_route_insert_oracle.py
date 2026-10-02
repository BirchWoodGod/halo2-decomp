#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops
from message_dispatch_oracle import Platform
from network_connection_oracle import Callbacks,Closed

def suite(h):
    rng=random.Random(0x92d10);ep=h.table;connections=ep+0x1000;address=ep+0x2000;record=ep+0x2100;local=ep+0x2200;packet=ep+0x3000;stub=0x3000800
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    original=[];native=[];iteration=0;coverage={'dispose':0,'callback':0,'success':0,'failure':0};frames={}
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,function,argument):
        events.append((function,argument,bytes(read(ep,0x224)),bytes(read(connections,0x400))))
        if events is original:coverage['callback']+=1
        if iteration%3==0:write(ep+0x20,pack(16))
        if iteration%5==0:write(address,pack(0x01020304));write(argument+0x44,pack(7))
    cb=Closed(lambda ctx,f,a:event(h.read,nw,native,f,a));callbacks=Callbacks(None,cb)
    clock=Operations(None,Ticks(),Provider());send=Ops();codec=Platform()
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x886e0:coverage['dispose']+=1;return
        if at==0x88650:frames['local']=esp-12;u.mem_write(esp-12,incoming);return
        argument=struct.unpack('<I',u.mem_read(esp+4,4))[0];event(u.mem_read,u.mem_write,original,at,argument)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for at in [stub,0x886e0,0x88650]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_endpoint_insert_route;fn.restype=C.c_uint8
    fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks),C.c_void_p]+[C.c_uint32]*7+[C.POINTER(C.c_uint8)]
    for iteration in range(1024):
        original.clear();native.clear();frames.clear();h.write(ep,rng.randbytes(0x224));h.write(connections,rng.randbytes(0x400));incoming=rng.randbytes(12);h.write(local,incoming)
        h.write(0x4d87d4,pack(connections));count=[0,1,2,15,16][iteration%5];h.write(ep+0x20,pack(count))
        width=[0,4,16,0xffff][iteration//5%4];addr=rng.randbytes(16)+struct.pack('<HH',1000,width);h.write(address,addr)
        selected=iteration//20%3;sequence=rng.getrandbits(32)
        for k in range(3):
            c=connections+k*0xf8;h.write(c,pack(ep));h.write(c+0x10,pack(0xffffffff)*2);h.write(c+0x3c,pack(record if k==0 else 0));h.write(c+0x44,pack(k))
            h.write(c+0x48,pack([0,0x40,0x80,0xc0][iteration//60%4]));h.write(c+0x54,pack([2,3,0xffffffff][iteration//240%3]))
            h.write(c+0x4c,pack(17 if iteration%2 else k));h.write(c+0x70,addr)
        h.write(record+4,pack(connections)+pack(stub))
        for k in range(16):
            h.write(ep+0x24+k*32,pack(k%3));h.write(ep+0x30+k*32,addr if k==0 else bytes(16)+struct.pack('<HH',1000,4))
        def run():
            value=fn(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),None,ep,selected,sequence,address,local,packet,local+16,(C.c_uint8*28)())
            if 'local' in frames:assert h.read(local,12)==bytes(h.u.mem_read(frames['local'],12))
            nw(local,incoming);coverage['success' if value else 'failure']+=1
            return value
        h.call('endpoint_insert_route',0x92d10,dict(esi=ep),[selected,sequence,address],run,255)
        assert original==native,iteration
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-route-insert-tests.json');args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_route_insert.c','include/halo2/network_route_insert.h','src/network_connection.c','src/network_routing.c','src/network_storage.c','tests/network_route_insert_oracle.py','tests/network_connection_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),boundary_coverage=coverage,comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Actual route lookup, connection dispose/close and route removal; full guest memory/AL and callback snapshots. Width/kind filters, same-index and equal-sequence cases, table capacity, callback changes to count/address. Connections have no allocated stream/storage; close states avoid sends. Not full connection open or gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
