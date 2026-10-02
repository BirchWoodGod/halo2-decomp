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
from network_storage_oracle import Operations as StorageOps
from async_tasks_oracle import Ops as AsyncOps
from message_dispatch_oracle import NativeCodec,Platform
from network_observer_state_oracle import Events

Destroy=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
Free=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32)
class Cleanup(C.Structure):
    _fields_=[('context',C.c_void_p),('destroy_provider',Destroy),('free_wrapper',Free)]

def suite(h):
    rng=random.Random(0x76ef0);observer=h.table;record=observer+0x5500;writer=observer+0x6000;connections=observer+0x7000;endpoint=observer+0x7800;table=observer+0x8000;local=observer+0x9000;packet=observer+0xa000;storage=observer+0xc000;small=observer+0xf000;pool=observer+0x11000;other=pool+0x100;storage_scratch=pool+0x800;stub=0x3000800
    original=[];native=[];frame={};iteration=0;incoming=bytes(16);storage_incoming=bytes(8)
    provider_wrapper=h.table+0x12000;other_wrapper=provider_wrapper+0x20;provider=provider_wrapper+0x100;vtable=provider_wrapper+0x200;large=h.table+0x13000;destroy_at=0x3000900
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,events,kind,arg):
        events.append((kind,arg,bytes(read(observer,0x4e00)),bytes(read(connections,0x400)),bytes(read(pool,0x800))))
        if iteration%3==0:
            write(observer+0xa8+14*0x528,pack(255)) # disposal must see later activation
            if kind=='async':write(0x4cf8d8,pack(other))
        return 0 if iteration%2 else 0x80004005
    cb=Closed(lambda ctx,f,arg:event(h.read,nw,native,'closed',arg));callbacks=Callbacks(None,cb)
    reg_release=Call(lambda ctx,arg:event(h.read,nw,native,'address',arg));registration=Registration(None,reg_release,Call())
    async_release=Call(lambda ctx,arg:event(h.read,nw,native,'async',arg));asyncops=AsyncOps(None,async_release)
    storageops=StorageOps();clock=Operations(None,Ticks(),Provider());send=Ops();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900);codec=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    register=h.lib.h2_messages_register_connection;register.argtypes=[C.POINTER(Memory),C.c_uint32]
    h.write(table,bytes(0x5a0));register(h.memory,table);h.write(table,h.read(table,0x5a0))
    def cleanup_event(read,write,log,kind,args):
        log.append((kind,args,bytes(read(0x4d87c4,0x40)),bytes(read(provider_wrapper,0x40)),bytes(read(large+0xa0ac,4)),bytes(read(large+0x2098,4))))
        if iteration%3==0:
            write(0x4d87f8,pack(other_wrapper));write(provider_wrapper,pack(0x12345678))
            write(0x4d87d4,pack(connections));write(0x4d87e4,pack(0xaabbccdd))
        return 0xdeadbeef
    destroy_cb=Destroy(lambda ctx,f,o,flags:cleanup_event(h.read,nw,native,'destroy',(f,o,flags)))
    free_cb=Free(lambda ctx,allocation:cleanup_event(h.read,nw,native,'free',(allocation,)))
    cleanup=Cleanup(None,destroy_cb,free_cb)
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x784a0:frame['mark']=bytes(u.mem_read(esp+4,4));return
        if at==0x78551:frame['mark']=bytes(u.mem_read(esp+0x14,4));return
        if at==0x88650:frame['message']=esp-12;u.mem_write(esp-12,frame.get('message_bytes',incoming[:12]));return
        if at==0x886d5:frame['message_bytes']=bytes(u.mem_read(frame['message'],12));return
        if at==0x94bf0:frame['storage']=esp-8;u.mem_write(esp-8,storage_incoming);return
        if at==0x94ddd:frame['storage_bytes']=bytes(u.mem_read(frame['storage'],8));return
        if at in [destroy_at,0x321379]:
            arg=struct.unpack('<I',u.mem_read(esp+4,4))[0]
            args=(at,u.reg_read(X.UC_X86_REG_ECX),arg) if at==destroy_at else (arg,)
            result=cleanup_event(u.mem_read,u.mem_write,original,'destroy' if at==destroy_at else 'free',args)
            u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+(8 if at==destroy_at else 4));return
        arg=struct.unpack('<I',u.mem_read(esp+4,4))[0];kind={stub:'closed',0x3cd344:'address',0x3cd172:'async'}[at]
        result=event(u.mem_read,u.mem_write,original,kind,arg)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+8)
    for at in [0x784a0,0x78551,0x88650,0x886d5,0x94bf0,0x94ddd,stub,0x3cd344,0x3cd172,destroy_at,0x321379]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    prefix=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks),C.POINTER(Registration),C.POINTER(StorageOps),C.POINTER(AsyncOps)]
    release=h.lib.h2_network_observer_release_slot;release.argtypes=prefix+[C.c_uint32]*5+[C.POINTER(C.c_uint8)];release.restype=None
    dispose=h.lib.h2_network_observer_dispose;dispose.argtypes=prefix+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];dispose.restype=None
    events=Events();closeall=h.lib.h2_network_observer_close_connections
    closeall.argtypes=prefix[:6]+[C.POINTER(Events),C.POINTER(StorageOps)]+[C.c_uint32]*4+[C.POINTER(C.c_uint8)];closeall.restype=None
    manager=h.lib.h2_network_connections_dispose
    manager.argtypes=prefix[:6]+[C.POINTER(Events),C.POINTER(StorageOps),C.POINTER(Cleanup)]+[C.c_uint32]*3+[C.POINTER(C.c_uint8)];manager.restype=None
    for wrapper in [False,True,'connections','manager']:
        observer=0x5291a0 if wrapper=='manager' else h.table
        for iteration in range(256):
            original.clear();native.clear();frame.clear();incoming=rng.randbytes(16);storage_incoming=rng.randbytes(8)
            h.write(local,incoming);h.write(storage_scratch,storage_incoming);h.write(observer,rng.randbytes(0x5000));h.write(writer,bytes(0x700));h.write(endpoint,bytes(0x588))
            h.write(observer+8,pack(writer));h.write(writer+8,struct.pack('<II',endpoint,table));h.write(0x4d87d4,pack(connections));h.write(0x4d87dc,pack(storage));h.write(0x4d87d8,pack(small))
            h.write(storage,rng.randbytes(0x2850));h.write(small,rng.randbytes(0x97c));h.write(storage+4,bytes([iteration%2]))
            for off in [0x18,0x1c,0x1834,0x1838]:h.write(storage+off,pack(0)) # real storage clear, empty queues
            for i in range(4):
                conn=connections+i*0xf8;rec=record+i*16;h.write(conn,rng.randbytes(0xf8))
                h.write(conn,struct.pack('<II',endpoint,writer));h.write(conn+0x3c,pack(rec if iteration%2 else 0));h.write(rec+4,struct.pack('<II',i,stub))
                h.write(conn+0x54,pack([2,3,5,0xffffffff][(iteration+i)%4]));h.write(conn+0x10,struct.pack('<II',0xffffffff if iteration%7==0 else 0,0xffffffff if iteration%11==0 else 0))
                h.write(conn+0x70,pack(0xdeadbeef)+bytes(12)+struct.pack('<HH',1001,4))
            for i in range(15):
                entry=observer+0xa8+i*0x528
                h.write(entry,pack(0 if i==14 or (iteration+i)%3==0 else 1))
                h.write(entry+12,pack(0xffffffff if i==14 or (iteration+i)%5==0 else i%4))
                h.write(entry+0x5c,bytes(20))
                if i!=14 and (iteration+i)%2:h.write(entry+0x5c,pack(0x00123456));h.write(entry+0x6e,b'\x04\x00')
                h.write(entry+0x70,pack(0xffffffff if i==14 else [0xffffffff,0x12340001,0x80010000,0x80020001,0x80030002][(iteration+i)%5]))
            if wrapper in ['connections','manager']:
                h.write(0x510548,b'\x01');h.write(0x51054c,pack(1500))
                for i in range(15):
                    entry=observer+0xa8+i*0x528
                    h.write(entry,pack(0 if (iteration+i)%3==0 else [1,6,7,8][i%4]))
                    h.write(entry+12,pack(i%4));h.write(entry+8,bytes(2))
                    h.write(entry+0x250,pack(0));h.write(entry+0x360,pack(0))
            h.write(pool,rng.randbytes(0x800))
            for a,entries,bitmap in [(pool,pool+0x400,pool+0x300),(other,pool+0x600,pool+0x304)]:
                for off,value in [(0x20,3),(0x24,12),(0x34,3),(0x38,3),(0x3c,3),(0x44,entries),(0x48,bitmap)]:h.write(a+off,pack(value))
                h.write(a+0x2a,bytes([8 if iteration%2 else 0]));h.write(bitmap,pack(7))
                for i in range(3):h.write(entries+i*12,struct.pack('<HHII',0x8001+i,0,0x1234+i,0))
            h.write(0x4cf8d8,pack(pool));h.write(0x4cf8d4,bytes([0 if iteration%13==0 else 255]));index=iteration%15
            if wrapper=='manager':
                h.write(large,rng.randbytes(0xa0b0));h.write(provider_wrapper,rng.randbytes(0x300))
                h.write(provider_wrapper,pack(provider if iteration%2 else 0));h.write(provider,pack(vtable));h.write(vtable+0x34,pack(destroy_at))
                h.write(0x4d87c4,rng.randbytes(0x40))
                for address,value in [(0x4d87d4,connections),(0x4d87d8,small),(0x4d87dc,storage),(0x4d87e8,large if iteration&2 else 0),(0x4d87ec,provider+0x40 if iteration&4 else 0),(0x4d87f0,provider+0x80 if iteration&8 else 0),(0x4d87f8,provider_wrapper if iteration&16 else 0),(0x4d87fc,0x12345678 if iteration&32 else 0)]:h.write(address,pack(value))
            def run():
                args=(h.memory,C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),C.byref(registration),C.byref(storageops),C.byref(asyncops))
                if wrapper=='manager':manager(*args[:6],C.byref(events),C.byref(storageops),C.byref(cleanup),local,packet,storage_scratch,(C.c_uint8*28)())
                elif wrapper=='connections':closeall(*args[:6],C.byref(events),C.byref(storageops),observer,local,packet,storage_scratch,(C.c_uint8*28)())
                elif wrapper:dispose(*args,observer,local,packet,storage_scratch,(C.c_uint8*28)())
                else:release(*args,observer,index,local,packet,storage_scratch,(C.c_uint8*28)())
                assert h.read(local,12)==frame.get('message_bytes',incoming[:12]),(wrapper,iteration,'message')
                assert h.read(local+12,4)==frame.get('mark',incoming[12:]),(wrapper,iteration,'mark')
                assert h.read(storage_scratch,8)==frame.get('storage_bytes',storage_incoming),(wrapper,iteration,'storage')
                nw(local,incoming);nw(storage_scratch,storage_incoming)
            if wrapper=='manager':h.call('network_connections_dispose',0x81f80,{},[],run)
            elif wrapper=='connections':h.call('observer_close_connections',0x78880,{},[observer],run)
            elif wrapper:h.call('observer_dispose',0x75a40,dict(ebx=observer),[],run)
            else:h.call('observer_release_slot',0x76ef0,dict(ecx=observer,eax=index),[],run)
            assert original==native,(wrapper,iteration)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-dispose-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_cleanup.c','include/halo2/network_cleanup.h','tests/network_observer_state_oracle.py','src/network_observer.c','include/halo2/network_observer.h','src/network_connection.c','src/network_storage.c','src/network_messages.c','src/network_address.c','src/network_routing.c','src/async_tasks.c','src/data_array.c','src/message_dispatch.c','tests/network_observer_dispose_oracle.py','tests/network_connection_oracle.py','tests/network_storage_oracle.py','tests/network_registration_oracle.py','tests/async_tasks_oracle.py','tests/message_dispatch_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original global connection-manager cleanup and observer connection-closing loop, slot and whole-observer disposal with detach/close/dispose/storage-clear/async-release/codec callees intact. Connection callback, SDK address/task release, virtual provider destructor and CRT wrapper free controlled. Global pointer resets, captured wrapper across callbacks and preserved padding checked. Empty storage queues, nonmatching or inactive writer flush; their nonempty/send behavior has separate coverage. Full memory, scratch and callback snapshots; inactive slots retained, later slot activation, shared connections, invalid task handles, SDK failure, poisoned deletion and pool replacement. Not complete networking shutdown or game boot.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
