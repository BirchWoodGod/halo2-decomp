#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
from network_observer_tick_oracle import Context as TickContext,Request
from network_observer_query_oracle import QueryOps,Query,Events
from network_registration_oracle import Operations as Registration,Call
from text_format_oracle import Platform,Format
class Context(C.Structure):
    _fields_=[('tick',C.POINTER(TickContext)),('format',C.POINTER(Platform)),('local12c',C.c_uint32),('arguments16',C.c_uint32)]
def suite(h):
    s=h.table;observer=s;config=s+0x5000;connections=s+0x6000;streams=s+0x7000;storage=s+0xa000;local=s+0x15000;args=local+0x130;scratch=local+0x200;packet=s+0x16000
    rng=random.Random(0x78900);original=[];native=[];coverage={};frames={}
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    u32=lambda read,p:struct.unpack('<I',read(p,4))[0]
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,kind,values):
        shown=(values[1],values[2],bytes(read(values[3],16))) if kind=='format' else values
        log.append((kind,shown,bytes(read(observer,0x5000)),bytes(read(connections,0x400))))
        if log is original:coverage[kind]=coverage.get(kind,0)+1
        if kind=='format':
            output='.'.join(str(v) for v in struct.unpack('<IIII',read(values[3],16))).encode()
            write(values[0],output+b'\0')
            if case%5==0:write(observer+0xa8+14*0x528,pack(4))
            return len(output)
        if kind=='ticks':return 100+len(log)
        if kind=='query':return 2
        return 0
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks',()));clock=Operations(None,tick,Provider())
    querycb=Query(lambda ctx,ip:event(h.read,nw,native,'query',(ip,)));query=QueryOps(None,querycb)
    releasecb=Call(lambda ctx,ip:event(h.read,nw,native,'release',(ip,)));registration=Registration(None,releasecb,Call());events=Events()
    fmtcb=Format(lambda ctx,d,n,f,a:event(h.read,nw,native,'format',(d,n,f,a)));formatter=Platform(None,fmtcb)
    ptr=lambda obj:C.cast(C.pointer(obj),C.c_void_p).value
    workspace=(C.c_uint8*28)();tc=TickContext(ptr(clock),None,None,None,ptr(registration),ptr(events),None,ptr(query),None,None,Request(),scratch,scratch+4,scratch+32,scratch+64,scratch+72,packet,workspace)
    ctx=Context(C.pointer(tc),C.pointer(formatter),local,args)
    def hook(u,at,size,data):
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x78900:frames['main']=sp-0x12c;u.mem_write(frames['main'],seed[:0x12c]);return
        if at in [0x82060,0x76f50,0x76ff0,0x776a0]:
            label={0x82060:'allocate',0x76f50:'refresh',0x76ff0:'update',0x776a0:'tick'}[at];coverage[label]=coverage.get(label,0)+1;return
        if at==0x321980:kind='format';values=struct.unpack('<IIII',u.mem_read(sp+4,16));purge=0
        elif at==0x3314b0:kind='ticks';values=();purge=0
        else:kind='query' if at==0x3cd35a else 'release';values=(u32(u.mem_read,sp+4),);purge=4
        value=event(u.mem_read,u.mem_write,original,kind,values)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,u32(u.mem_read,sp));u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x78900,0x82060,0x76f50,0x76ff0,0x776a0,0x321980,0x3314b0,0x3cd35a,0x3cd344]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_observer_rebuild_connections;fn.argtypes=[C.POINTER(Memory),C.POINTER(Context),C.c_uint32];fn.restype=None
    for case in range(256):
        original.clear();native.clear();frames.clear();h.write(observer,bytes(0x5100));h.write(observer+8,pack(s+0x5200));h.write(s+0x5200,bytes(0x700));h.write(observer+16,pack(config));h.write(config+0x6c,pack(0x7fffffff))
        h.write(connections,bytes(0x400));h.write(streams,bytes(0x2600));h.write(storage,bytes(0xa140))
        h.write(0x4d8ba0,bytes([case%3]));h.write(0x4d87d0,pack([0,1,2,4][case//3%4]));h.write(0x4d87d4,pack(connections)+pack(streams)+pack(storage));h.write(0x510548,bytes([case%2]));h.write(0x51054c,pack(100))
        for i in range(4):
            h.write(connections+i*0xf8+0x10,pack(0xffffffff)*2)
            if case%7==0:h.write(connections+i*0xf8+0x54,pack(2))
        for i in range(15):
            entry=observer+0xa8+i*0x528;active=(case+i)%4==0
            h.write(entry,pack([1,3,4,6,7][case//12%5] if active else 0));h.write(entry+0x14,rng.randbytes(36));h.write(entry+0x5c,pack(0x00123456)+bytes(12)+struct.pack('<HH',1000,4))
        seed=rng.randbytes(0x280);h.write(local,seed)
        def run():
            fn(h.memory,C.byref(ctx),observer)
            assert h.read(local,0x12c)==bytes(h.u.mem_read(frames['main'],0x12c)),(case,'locals')
            nw(local,seed)
        try:h.call('rebuild_connections',0x78900,{},[observer],run)
        except U.UcError:
            print('failure',case,hex(h.u.reg_read(X.UC_X86_REG_EIP)),[(e[0],e[1]) for e in original]);raise
        assert original==native,(case,'events')
    assert all(coverage.get(k) for k in ['allocate','refresh','update','tick','query','format']),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-rebuild-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_observer_rebuild.c','include/halo2/network_observer_rebuild.h','tests/network_observer_rebuild_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((lib.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,coverage=coverage,source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},scope='Actual allocation, refresh, update, tick and storage/stream allocation. Full memory/main frame/callback snapshots, occupied and exhausted pools and formatter activation of later slot. CRT formatting, SDK clock/query/release controlled. No consumer callbacks or live socket I/O.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
