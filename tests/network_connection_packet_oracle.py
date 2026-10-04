#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE
from network_send_oracle import Ops,Send,Error
from network_state_oracle import Operations,Ticks,Provider
P=lambda n:struct.pack('<I',n&0xffffffff)
def suite(h):
    conn=h.table;endpoint=conn+0x1000;socket=conn+0x2000;stream=conn+0x2100;primary=conn+0x2200;secondary=conn+0x2900;scratch=conn+0x4000;out=conn+0x6000;rng=random.Random(0x931a0)
    original=[];native=[];frame={};incoming=bytes(28);coverage=dict(submit=0,send=0,error=0,ticks=0,loopback1=0,loopback2=0,rejected=0,aliases=0)
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    def event(read,write,log,kind,args):
        packet=frame['packet'] if log is original else scratch
        log.append((kind,args,bytes(read(conn,0x100)),bytes(read(endpoint,0x588)),bytes(read(packet,0x824))))
        if log is original:coverage[kind]+=1
        if kind=='ticks' and case%3==0:
            write(conn+0x70,P(0xabcdef01));write(packet+0x1c,P(17));write(packet+0x620,P(0xfffffff0))
        if kind=='send' and case%5==0:write(socket,P(19))
        return [0,1,0xffffffff,0x1234ffff][case%4] if kind=='send' else [0,0x2733,0x2751][case%3] if kind=='error' else 1500
    send=Send(lambda ctx,handle,data,n,flags,addr,length:event(h.read,nw,native,'send',(handle,bytes(h.read(data,n)),n,flags,C.string_at(addr,28),length)))
    error=Error(lambda ctx:event(h.read,nw,native,'error',()));ops=Ops(None,send,error)
    tick=Ticks(lambda ctx:event(h.read,nw,native,'ticks',()));clock=Operations(None,tick,Provider())
    def hook(u,at,size,ctx):
        nonlocal incoming
        sp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x931a0:frame['packet']=((sp-4)&~7)-0x828;return
        if at==0x932dc:frame['packet_bytes']=bytes(u.mem_read(frame['packet'],0x824));return
        if at==0x932f0:coverage['submit']+=1;frame['packed']=sp-0x1004;return
        if at==0x933d6:
            n=struct.unpack('<I',u.mem_read(frame['packed'],4))[0];frame['packed_bytes']=bytes(u.mem_read(frame['packed'],4+n));return
        if at in [0x93234,0x93252,0x932d8]:coverage[{0x93234:'loopback1',0x93252:'loopback2',0x932d8:'rejected'}[at]]+=1;return
        if at==0xb5110:incoming=bytes(u.mem_read(sp-28,28));return
        if at==0x3cd254:
            handle,data,n,flags,addr,length=struct.unpack('<6I',u.mem_read(sp+4,24));value=event(u.mem_read,u.mem_write,original,'send',(handle,bytes(u.mem_read(data,n)),n,flags,bytes(u.mem_read(addr,28)),length));purge=24
        else:value=event(u.mem_read,u.mem_write,original,'ticks' if at==0x3314b0 else 'error',());purge=0
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,sp+4+purge)
    for at in [0x931a0,0x932dc,0x932f0,0x933d6,0x93234,0x93252,0x932d8,0xb5110,0x3cd254,0x3cd718,0x3314b0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_connection_send_packet;fn.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.POINTER(Ops)]+[C.c_uint32]*7+[C.POINTER(C.c_uint8)];fn.restype=None
    for case in range(1536):
        original.clear();native.clear();frame.clear();incoming=bytes(28);h.write(conn,rng.randbytes(0x100));h.write(endpoint,rng.randbytes(0x588));h.write(primary,rng.randbytes(0x700));h.write(secondary,rng.randbytes(0x300));h.write(scratch,rng.randbytes(0x1828));saved=h.read(scratch,0x1828)
        h.write(0x4d87d4,P(conn));h.write(conn+0x54,P([0,1,2,3,5,8,0xffffffff,0x80000000][case%8]));h.write(conn+0x48,bytes([0,0x40,0x80,0xc0][case//8%4]));h.write(conn+0x70,P(0x7f000001 if case%3==0 else 0x0a010203));h.write(conn+0x82,struct.pack('<H',[4,16,0,0xffff][case//9%4]))
        for j in range(4):h.write(endpoint+12+j*4,P(socket if case%13 else 0))
        h.write(socket,P(17));h.write(endpoint+0x20,P(1));h.write(endpoint+0x24,P(0));h.write(endpoint+0x2c,b'\0');h.write(endpoint+0x30,h.read(conn+0x70,20))
        for off in [0x228,0x3d8]:
            h.write(endpoint+off+0x10,P(100));h.write(endpoint+off+0x20,P(100));h.write(endpoint+off+0x28,P(case%20))
        h.write(0x510548,bytes([case%2]));h.write(0x51054c,P(1500));h.write(0x4d8b18,b'\1\1')
        n=[0,1,7,8,0x518,0x600,0x601,0xffffffff][case//5%8];extra=[0,1,31,0x200,0x201,0x80000000,0xffffffff][case//7%7];h.write(stream,P(primary)+P(n));h.write(out,P(0xabcdef01));optional=stream if case%5 else 0;output=out if case%7 else 0
        if case%11==0:output=stream+4;coverage['aliases']+=1
        def run():
            workspace=(C.c_uint8*28).from_buffer_copy(incoming)
            fn(h.memory,C.byref(clock),C.byref(ops),optional,0,endpoint,extra,secondary,output,scratch,workspace)
            assert h.read(scratch,0x824)==frame['packet_bytes'],(case,'packet')
            if 'packed_bytes' in frame:assert h.read(scratch+0x824,len(frame['packed_bytes']))==frame['packed_bytes'],(case,'packed')
            nw(scratch,saved)
        h.call('send_packet',0x931a0,dict(ecx=optional,eax=0),[endpoint,extra,secondary,output],run);assert original==native,(case,'callbacks')
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-connection-packet-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files=['src/network_connection_packet.c','include/halo2/network_connection_packet.h','tests/network_connection_packet_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),engine_library_sha256=H(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Connection packet assembly with original packet submission, accounting, packing, routing and socket-send callees intact. Full persistent memory, 0x824-byte packet and written packed scratch, SDK snapshots and address padding. Optional primary/output, signed state/secondary gates, loopback flags, payload limits, failures, callback mutation and output aliasing. SDK ticks/send/error controlled; replacement stack scratch restored. No live network or complete packet construction/gameplay.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
