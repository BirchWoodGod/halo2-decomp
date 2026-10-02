#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_send_oracle import Ops
from network_connection_oracle import Callbacks
from network_registration_oracle import Operations as Registration,Call
from message_dispatch_oracle import NativeCodec,Platform
StateOne=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32)
Connection=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
Query=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32)
class QueryOps(C.Structure):
    _fields_=[('context',C.c_void_p),('query',Query)]
class Events(C.Structure):
    _fields_=[('context',C.c_void_p),('state_one',StateOne),('connection',Connection)]

def suite(h):
    rng=random.Random(0x76f50);observer=h.table;writer=observer+0x3000;conn=observer+0x4000;alternate=conn+0x100;objects=observer+0x4500;vtable=objects+0x100;local=observer+0x5000;packet=observer+0x6000
    querylocal=local+32;queryseed=bytes(4);coverage={}
    state_at=0x3000800;connection_at=0x3000900;original=[];native=[];iteration=0;entry=0;direct=False;frame={};incoming=bytes(16)
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,kind,args):
        log.append((kind,args,bytes(read(observer,0x1800)),bytes(read(conn,0x200)),bytes(read(0x510548,12))))
        if log is original:coverage[kind]=coverage.get(kind,0)+1
        if kind=='query':
            result=[0,1,2,3,4,0xffffffff,0x80000000][iteration//(12 if mode=='refresh' else 24)%7]
            if log is original:
                label='query:'+mode+':'+str(struct.unpack('<I',read(entry,4))[0])+':'+str(result);coverage[label]=coverage.get(label,0)+1
            if iteration%5==0:write(entry,pack(7));write(entry+0x6e,b'\0\0')
            return result
        if kind=='ticks':
            n=sum(x[0]=='ticks' for x in log)
            if direct and iteration%11==0:write(entry,pack(1))
            if iteration%7==0:write(0x4d87d4,pack(alternate))
            return (0xfffffff0+n*17+iteration)&0xffffffff
        if kind in ['state','connection']:
            if iteration%3==0:
                value=read(entry+9,1)[0];write(entry+9,bytes([value^8]));write(observer+0x14+3*36,pack(objects+16))
                write(entry+0x10,pack(0xabcdef01))
            if kind=='state' and iteration%5==0:write(entry,pack(0))
        if kind=='release' and iteration%2:write(entry+0x5c,bytes([0xbb])*20)
        return 0x80004005
    querycb=Query(lambda ctx,v:event(h.read,nw,native,'query',(v,)));queryops=QueryOps(None,querycb)
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks',()));clock=Operations(None,tick,Provider())
    state_cb=StateOne(lambda ctx,f,o,i:event(h.read,nw,native,'state',(f,o,i)))
    connection_cb=Connection(lambda ctx,f,o,i,v,c:event(h.read,nw,native,'connection',(f,o,i,v,c)));events=Events(None,state_cb,connection_cb)
    release=Call(lambda ctx,v:event(h.read,nw,native,'release',(v,)));registration=Registration(None,release,Call());send=Ops();callbacks=Callbacks()
    codec=Platform();context=NativeCodec(h.memory,C.pointer(clock),packet+0x1900)
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init(C.byref(codec),C.byref(context))
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x7acf0:frame['query']=esp-4;return
        if at in [0x7ad15,0x7ad19,0x7ad20,0x7ad27,0x7ad2e]:frame['query_bytes']=bytes(u.mem_read(frame['query'],4));return
        if at==0x784a0:frame['mark']=bytes(u.mem_read(esp+4,4));return
        if at==0x78551:frame['mark']=bytes(u.mem_read(esp+0x14,4));return
        if at==0x3cd35a:kind='query';args=struct.unpack('<I',u.mem_read(esp+4,4));purge=4
        elif at==0x3314b0:kind='ticks';args=();purge=0
        elif at==0x3cd344:kind='release';args=struct.unpack('<I',u.mem_read(esp+4,4));purge=4
        else:
            kind='state' if at==state_at else 'connection';purge=4 if kind=='state' else 12
            args=(at,u.reg_read(X.UC_X86_REG_ECX),*struct.unpack('<'+('I' if purge==4 else 'III'),u.mem_read(esp+4,purge)))
        result=event(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EAX,result);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for at in [0x7acf0,0x7ad15,0x7ad19,0x7ad20,0x7ad27,0x7ad2e,0x3cd35a,0x784a0,0x78551,0x3314b0,0x3cd344,state_at,connection_at]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    address_query=h.lib.h2_network_address_query;address_query.argtypes=[C.POINTER(Memory),C.POINTER(QueryOps)]+[C.c_uint32]*2;address_query.restype=C.c_uint32
    observer_query=h.lib.h2_network_observer_query;observer_query.argtypes=[C.POINTER(Memory),C.POINTER(QueryOps)]+[C.c_uint32]*3;observer_query.restype=C.c_uint32
    refresh=h.lib.h2_network_observer_refresh_address
    refresh.argtypes=[C.POINTER(Memory),C.POINTER(QueryOps),C.POINTER(Operations),C.POINTER(Ops),C.POINTER(Platform),C.POINTER(Callbacks),C.POINTER(Registration),C.POINTER(Events)]+[C.c_uint32]*5+[C.POINTER(C.c_uint8)];refresh.restype=None
    for mode in ['address','observer','refresh']:
        count=512
        for iteration in range(count):
            original.clear();native.clear();frame.clear();index=iteration%3;entry=observer+0xa8+index*0x528
            h.write(observer,rng.randbytes(0x1800));h.write(writer,bytes(0x700));h.write(conn,rng.randbytes(0x200));h.write(observer+8,pack(writer))
            state=[0,1,2,3,4,5,6,7,8,9,0xffffffff,0x80000000][(iteration if mode=='refresh' else iteration//6)%12];h.write(entry,pack(state));h.write(entry+8,bytes([(iteration//10%4)*2,iteration%256]))
            h.write(entry+10,struct.pack('<H',[0,1,7,0xffff,0x8000][iteration//12%5]));h.write(entry+12,pack(0xffffffff if iteration%13==0 else 0))
            h.write(entry+0x10,pack(0x1234 if iteration%3 else 0x5678))
            h.write(entry+0x250,pack([0,1,16,32,0xffffffff][iteration%5]));h.write(entry+0x360,pack([32,16,1,0][iteration%4]))
            width=[0,4,16,0xffff,5,0x8000][iteration%6]
            ip=[0,0x00123456,0x7f000001,0xffffffff][iteration//6%4]
            if mode=='refresh':width=[4,0,16,0xffff][iteration//84%4];ip=0x00123456
            h.write(entry+0x5c,pack(ip)+bytes(12)+struct.pack('<HH',1001,width))
            if width==16:
                h.write(entry+0x5c,bytes(16))
                if iteration//6%3:h.write(entry+0x5c+(iteration//18%8)*2,b'\1')
            h.write(entry+0x3c,pack(iteration%6));h.write(0x4d87d4,pack(conn));h.write(conn+0x54,pack(2));h.write(alternate+0x54,pack(2));h.write(conn+0x58,pack([0,1,2,3,5,8,9,10,0xffffffff][iteration//50%9]));h.write(conn+0x4c,pack(0x1234))
            h.write(0x510548,bytes([iteration//5%2]));h.write(0x51054c,pack(iteration));h.write(0x485ac0,struct.pack('<H',[0,1,60,0x7fff,0x8000,0xffff][iteration%6]));h.write(0x4e6398,struct.pack('<II',iteration%100,0x12345678));h.write(0x45dbcc,pack(0x3f800000))
            for i in range(5):h.write(objects+i*4,pack(vtable))
            h.write(vtable+12,struct.pack('<II',connection_at,state_at))
            for i in range(4):h.write(observer+0x14+i*36,pack(objects+i*4))
            incoming=rng.randbytes(16);h.write(local,incoming)
            queryseed=rng.randbytes(4);h.write(querylocal,queryseed)
            address=0 if iteration%17==0 else entry+0x5c
            query_observer=((-0xa8-index*0x528-0x5c)&0xffffffff) if iteration%31==0 else observer
            def run():
                if mode=='address':result=address_query(h.memory,C.byref(queryops),address,querylocal)
                elif mode=='observer':result=observer_query(h.memory,C.byref(queryops),query_observer,index,querylocal)
                else:
                    refresh(h.memory,C.byref(queryops),C.byref(clock),C.byref(send),C.byref(codec),C.byref(callbacks),C.byref(registration),C.byref(events),observer,index,querylocal,local,packet,(C.c_uint8*28)());result=None
                assert h.read(querylocal,4)==frame.get('query_bytes',queryseed),(mode,iteration,'query scratch')
                assert h.read(local,12)==incoming[:12],(mode,iteration,'close scratch')
                assert h.read(local+12,4)==frame.get('mark',incoming[12:]),(mode,iteration,'detach scratch')
                nw(querylocal,queryseed);nw(local,incoming);return result
            addr={'address':0x7acf0,'observer':0x78580,'refresh':0x76f50}[mode]
            regs={'address':dict(ecx=address),'observer':dict(ecx=query_observer,eax=index),'refresh':dict(edi=observer,esi=index)}[mode]
            try:h.call(mode,addr,regs,[],run,None if mode=='refresh' else 0xffffffff)
            except Exception:
                print(mode,iteration,hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
            assert original==native,(mode,iteration)
    assert coverage.get('query') and coverage.get('release') and coverage.get('ticks'),coverage
    for value in [0,1,2,3,4,0xffffffff,0x80000000]:assert coverage.get('query:refresh:3:'+str(value)),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-query-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_query.c','include/halo2/network_observer_query.h','src/network_address.c','src/network_resolution.c','tests/network_observer_query_oracle.py','src/network_observer.c','include/halo2/network_observer.h','src/network_endpoint.c','src/network_messages.c','src/network_address.c','tests/network_observer_state_oracle.py','tests/network_state_oracle.py','tests/network_registration_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),boundary_coverage=coverage,comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='address/observer SDK-status queries and address-state refresh with actual validation, conversion, detach and set-state. SDK query/release/ticks controlled with mutation. Full memory/returns and local scratch, null/wrapped addresses, widths, signed states, SDK results and retry counters. Connections state2 and inactive writer avoid close/flush, covered separately. Not full admission or playable startup.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
