#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops
from network_connection_oracle import Callbacks,Closed
from network_registration_oracle import Operations as Registration,Call
from message_dispatch_oracle import NativeCodec,Platform

def suite(h):
    rng=random.Random(0x784a0);observer=h.table;writer=observer+0x3000;connection=observer+0x4000;record=observer+0x4500;endpoint=observer+0x5000;table=observer+0x6000;local=observer+0x7000;packet=observer+0x8000;stub=0x3000800
    original=[];native=[];frame={};iteration=0;entry=0;incoming=bytes(16)
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,value):
        events.append((kind,value,bytes(read(observer,0x1800)),bytes(read(writer,0x700)),bytes(read(connection,0xf8))))
        if iteration%3==0:
            write(entry+0x3c,pack(2));write(entry+0x5c,pack(0x00556677));write(entry+0x6e,b'\x04\x00')
        if kind=='release' and iteration%2:write(entry+0x5c,bytes([0xaa])*20)
        return 0x80004005
    cb=Closed(lambda ctx,function,arg:event(h.read,nw,native,'closed',arg));callbacks=Callbacks(None,cb)
    release=Call(lambda ctx,arg:event(h.read,nw,native,'release',arg));registration=Registration(None,release,Call())
    clock=Operations(None,Ticks(),Provider());send=Ops();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x88650:frame['message']=esp-12;u.mem_write(esp-12,incoming[:12]);return
        if at==0x886d5:frame['bytes']=bytes(u.mem_read(frame['message'],12));return
        argument=struct.unpack('<I',u.mem_read(esp+4,4))[0]
        value=event(u.mem_read,u.mem_write,original,'closed' if at==stub else 'release',argument)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for at in [0x88650,0x886d5,stub,0x3cd344]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_detach
    fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks),C.POINTER(Registration)]+[C.c_uint32]*6+[C.POINTER(C.c_uint8)];fn.restype=None
    for iteration in range(512):
        original.clear();native.clear();frame.clear();index=[0,1,3][iteration%3];entry=observer+0xa8+index*0x528
        h.write(observer,rng.randbytes(0x1800));h.write(writer,bytes(0x700));h.write(connection,rng.randbytes(0xf8));h.write(endpoint,bytes(0x588))
        h.write(observer+8,pack(writer));h.write(entry+12,pack(0xffffffff if iteration%7==0 else 0));h.write(0x4d87d4,pack(connection))
        h.write(connection,struct.pack('<II',endpoint,writer));h.write(connection+0x3c,pack(record if iteration%2 else 0));h.write(record+4,struct.pack('<II',0x11223344,stub))
        h.write(connection+0x54,pack([0,2,3,5,0xffffffff][iteration%5]));h.write(connection+0x70,pack(0xdeadbeef)+bytes(12)+struct.pack('<HH',1001,4))
        h.write(writer+8,struct.pack('<II',endpoint,table))
        width=[0,4,16,0xffff,8][iteration//5%5];h.write(entry+0x6e,struct.pack('<H',width))
        h.write(entry+0x5c,pack([0,1,0x00123456,0x01123456][iteration//25%4]))
        if iteration%11==0:h.write(entry+0x5c,bytes(16))
        h.write(entry+0x3c,pack([0,1,3,4,0xffffffff][iteration//3%5]))
        mark=[0,1,255,256,0xffffffff][iteration//7%5];reason=[1,3,6,17][iteration//9%4]
        incoming=rng.randbytes(16);h.write(local,incoming)
        def run():
            fn(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),C.byref(registration),observer,index,mark,reason,local,packet,(C.c_uint8*28)())
            assert h.read(local,12)==frame.get('bytes',incoming[:12]),iteration
            assert h.read(local+12,4)==bytes(h.u.mem_read(0x2008004,4)),iteration
            nw(local,incoming)
        h.call('observer_detach',0x784a0,dict(ecx=observer,eax=index),[mark,reason],run)
        assert original==native,iteration

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_observer.c','include/halo2/network_observer.h','src/network_connection.c','src/network_messages.c','src/network_address.c','src/network_routing.c','src/message_dispatch.c','tests/network_observer_oracle.py','tests/network_connection_oracle.py','tests/network_registration_oracle.py','tests/message_dispatch_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original observer detach with connection close, queue/codec, address matching and IPv4 conversion intact. Connection callback and SDK address release controlled. Full memory, original message/argument scratch and callback snapshots; address widths, zero addresses, low-byte mark, bit range, state/reason gates and callback mutation. Queue flush takes inactive/mismatched-address branches here; matching flush/send separately covered. No observer state machine, full shutdown or game boot.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
