#!/usr/bin/env python3
import argparse, ctypes as C, hashlib, json, random, struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT, Memory, EXPECTED
from network_state_oracle import Operations, Ticks, Provider
from network_observer_tick_oracle import Context
from network_observer_query_oracle import Events, StateOne, Connection
from text_format_oracle import Platform, Format
from async_tasks_oracle import Ops as AsyncOps, Call as AsyncCall
from network_registration_oracle import Operations as Registration, Call as RegistrationCall

class Admission(C.Structure):
    _fields_=[('network',C.POINTER(Context)),('async_ops',C.c_void_p),('format',C.POINTER(Platform)),
              ('identity36',C.c_uint32),('label256',C.c_uint32),('arguments24',C.c_uint32)]

def suite(h):
    rng=random.Random(0x76aa0); observer=h.table; writer=observer+0x5000;config=observer+0x6000
    connections=observer+0x7000; streams=observer+0x8000; storage=observer+0xb000
    objects=observer+0x18000; vtable=objects+0x100; identity=objects+0x200
    task_pool=observer+0x19000
    scratch=observer+0x1a000; packet=observer+0x1b000; callback_at=0x3000900
    original=[];native=[];coverage={};iteration=0;chosen=0
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    read32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,*args):
        events.append((kind,args,bytes(read(observer,0x4e00)),bytes(read(connections,0x400))))
        if events is original:coverage[kind]=coverage.get(kind,0)+1
        if kind=='ticks':
            ordinal=sum(x[0]=='ticks' for x in events)
            if iteration%7==0:
                write(identity+20,pack(ordinal));write(config+0xfc,pack(ordinal%5))
            if iteration%11==0:write(observer+0xa8+chosen*0x528+8,b'\2')
            return 100+ordinal
        if kind=='notify':write(observer+0xa8+chosen*0x528+0x98,pack(iteration))
        if kind=='address_release':
            write(identity+24,pack(iteration));return 0x80004005 if iteration%3 else 0
        return 0
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks'));clock=Operations(None,tick,Provider())
    notify=Connection(lambda ctx,f,o,i,v,a:event(h.read,nw,native,'notify',f,o,i,v,a))
    events=Events(None,StateOne(),notify);network=Context()
    network.clock=C.cast(C.pointer(clock),C.c_void_p).value
    network.events=C.cast(C.pointer(events),C.c_void_p).value
    release_address=RegistrationCall(lambda ctx,ip:event(h.read,nw,native,'address_release',ip))
    registration=Registration(None,release_address,RegistrationCall())
    network.registration=C.cast(C.pointer(registration),C.c_void_p).value
    network.detach16=scratch+0x200;network.storage8=scratch+0x220;network.packet=packet
    workspace=(C.c_uint8*28)();network.workspace28=workspace
    def format_event(read,write,events,dest,limit,fmt,args):
        n=4 if fmt==0x450c38 else 6
        values=struct.unpack('<'+'I'*n,read(args,n*4))
        event(read,write,events,'format',limit,fmt,values)
        text=('.'.join(str(v) for v in values) if n==4 else '!MAC='+''.join(f'{v:02X}' for v in values)).encode()
        write(dest,text[:limit]+b'\0');return len(text)
    fmt_cb=Format(lambda ctx,d,n,f,a:format_event(h.read,nw,native,d,n,f,a))
    async_cb=AsyncCall(lambda ctx,task:event(h.read,nw,native,'async_release',task))
    async_ops=AsyncOps(None,async_cb)
    fmt=Platform(None,fmt_cb);context=Admission(C.pointer(network),C.cast(C.pointer(async_ops),C.c_void_p),C.pointer(fmt),scratch,scratch+64,scratch+0x180)
    def hook(u,at,size,ctx):
        sp=u.reg_read(X.UC_X86_REG_ESP);purge=0
        if at==0x3314b0:value=event(u.mem_read,u.mem_write,original,'ticks')
        elif at==0x321980:
            args=struct.unpack('<4I',u.mem_read(sp+4,16));value=format_event(u.mem_read,u.mem_write,original,*args)
        elif at==0x3cd172:
            purge=4;value=event(u.mem_read,u.mem_write,original,'async_release',read32(u.mem_read,sp+4))
        elif at==0x3cd344:
            purge=4;value=event(u.mem_read,u.mem_write,original,'address_release',read32(u.mem_read,sp+4))
        else:
            args=struct.unpack('<3I',u.mem_read(sp+4,12));purge=12
            value=event(u.mem_read,u.mem_write,original,'notify',at,u.reg_read(X.UC_X86_REG_ECX),*args)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,read32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x3314b0,0x321980,0x3cd172,0x3cd344,callback_at]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_admit;fn.argtypes=[C.POINTER(Memory),C.POINTER(Admission)]+[C.c_uint32]*3;fn.restype=C.c_uint32
    for iteration in range(1024):
        original.clear();native.clear();h.write(observer,rng.randbytes(0x1b000));seed=h.read(scratch,0x240)
        chosen=iteration%15;consumer=iteration%4;mode=iteration//15%4
        h.write(identity,rng.randbytes(36));h.write(observer+16,pack(config))
        h.write(writer,bytes(0x700));h.write(observer+8,pack(writer))
        h.write(vtable+12,pack(callback_at))
        for j in range(4):h.write(objects+j*8,pack(vtable));h.write(observer+0x14+j*36,pack(objects+j*8))
        for j in range(15):
            e=observer+0xa8+j*0x528
            h.write(e,pack(3));h.write(e+9,b'\1');h.write(e+12,pack(0xffffffff));h.write(e+0x70,pack(0xffffffff));h.write(e+0x5c,bytes(20))
        entry=observer+0xa8+chosen*0x528
        if mode==0:h.write(entry+0x14,h.read(identity,36))
        if mode==1:h.write(entry,pack(0))
        if mode==2:h.write(entry+9,b'\0')
        if mode in [1,2] and iteration%4:
            h.write(entry+0x5c,pack(0x00010203 if iteration%2 else 0x01020304)+bytes(14)+b'\4\0')
        h.write(entry+8,bytes([2 if iteration%2 else 0]))
        for j in range(4):
            conn=connections+j*0xf8;h.write(conn+0x10,pack(0xffffffff)*2);h.write(conn+0x54,pack(0 if j>=iteration%5 else 2))
            h.write(streams+j*0x97c+4,b'\0');h.write(storage+j*0x2850+4,b'\0')
        if mode==2 and iteration%3:
            h.write(entry+12,pack(0));h.write(connections+0x54,pack(1))
            h.write(connections+0x10,pack(1)*2)
            h.write(streams+0x97c+4,b'\1')
            coverage['reclaim_connection']=coverage.get('reclaim_connection',0)+1
        if mode==2 and iteration%5:
            h.write(task_pool,bytes(0x200))
            for off,val in [(0x20,1),(0x24,12),(0x34,1),(0x38,1),(0x3c,1),(0x44,task_pool+0x100),(0x48,task_pool+0x80)]:h.write(task_pool+off,pack(val))
            h.write(task_pool+0x80,pack(1));h.write(task_pool+0x100,struct.pack('<HHII',0x8002,0,task_pool+0x180,0))
            h.write(0x4cf8d4,b'\1');h.write(0x4cf8d8,pack(task_pool));h.write(entry+0x70,pack(0x80020000))
        h.write(0x4d8ba0,bytes([iteration%3!=0]));h.write(0x4d87d0,pack(4))
        for at,value in [(0x4d87d4,connections),(0x4d87d8,streams),(0x4d87dc,storage)]:h.write(at,pack(value))
        h.write(0x510548,bytes([iteration%2]));h.write(0x51054c,pack(iteration));h.write(config+0xf8,pack([0,1,19,20,123,0xffffffff,0x80000000,0x7fffffff][iteration%8]));h.write(config+0xfc,pack(iteration%5))
        h.write(0x4cf6e8,pack(1000));h.write(0x4cf70c,bytes(16))
        def run():
            result=fn(h.memory,C.byref(context),observer,consumer,identity)
            key=('failure' if result==0xffffffff else 'success')+':mode'+str(mode)
            coverage[key]=coverage.get(key,0)+1
            # Native scratch substitutes for original stack locals; compare
            # formatter arguments/events separately, exclude only local storage.
            nw(scratch,seed)
            return result
        h.call('admit_mode_'+str(mode),0x76aa0,{},[observer,consumer,identity],run,0xffffffff)
        assert original==native,(iteration,mode,[(e[0],e[1]) for e in original],[(e[0],e[1]) for e in native])
    assert coverage.get('async_release') and coverage.get('reclaim_connection')
    assert coverage.get('address_release')
    assert all(coverage.get('success:mode'+str(i)) for i in range(3))
    assert coverage.get('failure:mode3') and coverage.get('failure:mode1') and coverage.get('failure:mode2')
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-admit-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_admit.c','include/halo2/network_observer_admit.h','src/text_format.c','tests/network_observer_admit_oracle.py','include/halo2/text_format.h','src/network_connection_allocate.c','src/network_slot_alloc.c','src/network_observer.c','src/network_endpoint.c','tests/network_observer_tick_oracle.py','tests/network_registration_oracle.py','tests/async_tasks_oracle.py','tests/text_format_oracle.py']
    report=dict(passed=True,total_comparisons=sum(h.counts.values()),comparisons=h.counts,coverage=coverage,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Admission with actual recovered allocation/reset/detach/dispose/task-release callees. Original CRT formatting, SDK task release and address-release controlled boundaries; disjoint native scratch restored. Existing identity, new slot, reclaim and full observer. Reclaimed connections state1 with owned stream and inactive storage; actual task pool deletion. Registered/unregistered IPv4 cleanup with callback identity mutation and ignored SDK errors; inactive writer means no packet flush. No close packets or live network.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
