#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops
from message_dispatch_oracle import NativeCodec,Platform
Closed=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32)
class Callbacks(C.Structure):
    _fields_=[('context',C.c_void_p),('closed',Closed)]

def suite(h):
    rng=random.Random(0x77580);writer=h.table;table=writer+0x1000;endpoint=writer+0x2000;other=writer+0x2600;connections=writer+0x3000;records=writer+0x4000;local=writer+0x4800;packet=writer+0x5000;alternate=writer+0x7000;stub=0x3000800
    observer=writer+0x8000;storage=writer+0xa000;entry=0;coverage={}
    original=[];native=[];iteration=0;drain=False;frame={};incoming=bytes(12)
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,function,argument):
        events.append((function,argument,bytes(read(writer,0x700)),bytes(read(endpoint,0x1800)),bytes(read(alternate,0x400))))
        if iteration%3==0:
            write(argument,pack(other));write(argument+0x44,pack(2));write(argument+0x70,bytes(range(20)))
        if iteration%7==0:
            write(0x4d87d4,pack(alternate));write(endpoint+0x20,pack(2))
        write(argument+0x54,pack(99)) # final close state must overwrite this
    cb=Closed(lambda ctx,function,argument:event(h.read,nw,native,function,argument));callbacks=Callbacks(None,cb)
    def tick_event(read,write,events):
        events.append(('ticks',bytes(read(observer,0x1600)),bytes(read(0x510548,8)),bytes(read(0x4cf568,8))))
        if events is original:coverage['ticks']=coverage.get('ticks',0)+1
        if iteration%3==0:write(entry+0x98,pack(0x80000000));write(entry+0x9c,pack(0xffffffff));write(0x4cf56c,pack(17));write(0x4cf568,pack(3))
        if iteration%13==0:write(0x510548,b'\1');write(0x51054c,pack(101))
        return (0xfffffff0+len(events)*7+iteration)&0xffffffff
    tick=Ticks(lambda ctx:tick_event(h.read,nw,native));clock=Operations(None,tick,Provider());send=Ops();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x3314b0:
            value=tick_event(u.mem_read,u.mem_write,original);u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4);return
        if at==0x88650:
            coverage['close']=coverage.get('close',0)+1
            frame['local']=esp-12;u.mem_write(esp-12,incoming);return
        argument=struct.unpack('<I',u.mem_read(esp+4,4))[0];event(u.mem_read,u.mem_write,original,at,argument)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for at in [stub,0x88650,0x3314b0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    prefix=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks)]
    close=h.lib.h2_network_observer_retry_allowed;close.argtypes=prefix+[C.c_uint32]*5+[C.POINTER(C.c_uint8)];close.restype=C.c_uint8
    elapsed=h.lib.h2_network_elapsed;elapsed.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];elapsed.restype=C.c_uint32
    capacity=h.lib.h2_network_connection_send_capacity;capacity.argtypes=[C.POINTER(Memory),C.c_uint32];capacity.restype=C.c_uint32
    closeall=h.lib.h2_network_endpoint_close_connections;closeall.argtypes=prefix+[C.c_uint32]*3+[C.POINTER(C.c_uint8)];closeall.restype=None
    for mode in ['elapsed','capacity','retry']:
        for iteration in range(512):
            original.clear();native.clear();frame.clear();h.write(observer,rng.randbytes(0x1600));incoming=rng.randbytes(12);h.write(local,incoming)
            h.write(writer,bytes(0x700));h.write(writer+8,struct.pack('<II',endpoint,table))
            for ep in [endpoint,other]:
                h.write(ep,rng.randbytes(0x588));h.write(ep+0x20,pack([0,1,2,4,0xffffffff][iteration%5]))
                for i in range(4):h.write(ep+0x24+i*32,pack(i))
            h.write(0x4d87d4,pack(connections))
            for bank,base in enumerate([connections,alternate]):
                h.write(base,rng.randbytes(0x400))
                for i in range(4):
                    conn=base+i*0xf8;record=records+(bank*4+i)*16
                    h.write(conn,struct.pack('<II',endpoint,writer));h.write(conn+0x44,pack(i))
                    h.write(conn+0x3c,pack(record if (iteration+i)%4 else 0))
                    h.write(record+4,struct.pack('<II',conn,stub))
                    state=[0,1,2,3,5,0xffffffff,0x80000000,0x7fffffff][iteration%8] if not drain else [2,3,0xffffffff][(iteration+i)%3]
                    h.write(conn+0x54,pack(state));h.write(conn+0x70,rng.randbytes(20));h.write(conn+0x82,struct.pack('<H',4))
            index=iteration%4;identifier=iteration//4%4;missing=iteration%11==0
            h.write(observer+0xa8+index*0x528+12,pack(0xffffffff if missing else identifier))
            state=h.u32(connections+identifier*0xf8+0x54)
            entry=observer+0xa8+index*0x528
            h.write(entry+0x98,pack([0,1,0xfffffff0,0x80000000][iteration//4%4]));h.write(entry+0x9c,pack([0,5,0x7fffffff][iteration//16%3]))
            h.write(entry+0x5c,pack(0x00123456)+bytes(12)+struct.pack('<HH',1000,[0,4,16,0xffff][iteration//48%4]))
            h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack(iteration));h.write(0x4cf568,pack([0,1,17,0xffffffff,0x80000000][iteration//5%5]));h.write(0x4cf56c,pack([0,100,0xffffffff,0x7fffffff][iteration//25%4]))
            h.write(storage,bytes(0x5100));h.write(0x4d87dc,pack(storage))
            for k in range(2):
                h.write(storage+k*0x2850+0x18,pack([0,1,512,513,0x04000000,0xffffffff][iteration//8%6]));h.write(storage+k*0x2850+0x1c,pack(k))
            for k in range(4):h.write(connections+k*0xf8+0x14,pack(iteration%2));h.write(connections+k*0xf8+0x48,bytes([16 if iteration//48%2 else 0]))
            previous=rng.getrandbits(32);reason=[0,1,13,17,0xffffffff][iteration//8%5]

            def run():
                if mode=='elapsed':return elapsed(h.memory,C.byref(clock),previous)
                if mode=='capacity':return capacity(h.memory,connections+identifier*0xf8)
                result=close(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),observer,index,reason,local,packet,(C.c_uint8*28)())
                if 'local' in frame:assert h.read(local,12)==bytes(h.u.mem_read(frame['local'],12)),(mode,iteration)
                else:assert h.read(local,12)==incoming
                nw(local,incoming);return result
            address={'elapsed':0x75890,'capacity':0x89070,'retry':0x77580}[mode]
            regs={'elapsed':{},'capacity':dict(ecx=connections+identifier*0xf8),'retry':dict(ecx=observer,eax=index,edi=reason)}[mode]
            try:h.call(mode,address,regs,[previous] if mode=='elapsed' else [],run,255 if mode=='retry' else 0xffffffff)
            except Exception:
                print(mode,iteration,hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
            assert original==native,(mode,iteration)
    assert coverage.get('ticks') and coverage.get('close'),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-retry-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_retry.c','include/halo2/network_observer_retry.h','src/network_resolution.c','tests/network_observer_retry_oracle.py','src/network_observer_admission.c','include/halo2/network_observer_admission.h','tests/network_observer_admission_oracle.py','src/network_connection.c','include/halo2/network_connection.h','src/network_routing.c','src/network_messages.c','src/message_dispatch.c','tests/network_connection_oracle.py','tests/message_dispatch_oracle.py','tests/network_state_oracle.py','tests/network_send_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),boundary_coverage=coverage,comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='elapsed time, connection send capacity and observer retry eligibility. Actual connection-close/codec/queue/route callees; clock and connection callbacks controlled. Full memory/returns, close local scratch, wraparound and signed thresholds, timer/override mutation. Fresh writer, no packet flush. Not full observer admission or gameplay.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
