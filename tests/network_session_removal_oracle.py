#!/usr/bin/env python3
"""Membership removal with actual reservation lookup, detach and CRT memmove."""
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from engine_pools_oracle import BASE

def suite(h):
    rng=random.Random(0x5fe20);session=h.table;observer=session+0x8000;scratch=session+0xe000
    frames={};coverage={}
    pack=lambda n:struct.pack('<I',n&0xffffffff)
    def nw(p,b):C.memmove(h.pointer+p-BASE,b,len(b))
    def hook(u,at,size,ctx):
        if at==0x60200:frames['argument']=u.reg_read(X.UC_X86_REG_ESP)+4;coverage['remove_player']=coverage.get('remove_player',0)+1
        elif at==0x602a6:frames['argument_bytes']=bytes(u.mem_read(frames['argument'],4))
        elif at==0x62f40:coverage['reservation_lookup']=coverage.get('reservation_lookup',0)+1
        elif at==0x5f970:coverage['detach']=coverage.get('detach',0)+1
        else:coverage['memmove']=coverage.get('memmove',0)+1
    for at in [0x60200,0x602a6,0x62f40,0x5f970,0x320890]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    funcs={}
    for name,n in [('refresh_peer_flag',1),('remove_player',3),('remove_peer',3)]:
        f=getattr(h.lib,'h2_network_session_'+name);f.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*n;f.restype=None;funcs[name]=f
    for mode in funcs:
        for iteration in range(512):
            frames.clear();h.write(session,rng.randbytes(0x7900));h.write(observer,rng.randbytes(0x5400));seed=rng.randbytes(4);h.write(scratch,seed)
            count=1+iteration%16;players=min(count*4,16);selected=iteration//16%count;player=iteration%players
            h.write(session+8,pack(observer));h.write(session+0x10,pack([0,7,8,31,32,0xffffffff][iteration//16%6]))
            h.write(session+0x54,pack(count));h.write(session+0x741c,pack([0,1,3,4,5,6,7,8,9,0xffffffff][iteration//7%10]));h.write(session+0x765c,bytes([0 if iteration%4==0 else 255]))
            for off in [0x40,0x50,0x72d8]:h.write(session+off,pack([0,selected,count-1,0xffffffff][iteration//3%4]))
            for off in [0x4c,0x7618]:h.write(session+off,pack([0,1,0xffffffff,0x7fffffff][iteration//5%4]))
            mask=0;live=0
            for i in range(16):
                h.write(session+0x150+i*0x10c,pack(0))
                for j in range(4):h.write(session+0x154+i*0x10c+j*4,pack(0xffffffff))
                h.write(session+0x72e0+i*20,pack(0xffffffff if (iteration+i)%7==0 else i));h.write(session+0x72de+i*20,bytes([1 if (iteration+i)%13==0 else 0]))
                h.write(session+0x7668+i*36,bytes([0 if (iteration+i)%5==0 else 255]))
            for i in range(players):
                owner=i%count;slot=i//count;identity=session+0x1120+i*0x13c
                h.write(identity+12,pack(owner));h.write(identity+16,pack(slot))
                if (iteration+i)%4:
                    mask|=1<<i;live+=1;h.write(session+0x154+owner*0x10c+slot*4,pack(i));p=session+0x150+owner*0x10c;h.write(p,pack(h.u32(p)+1))
                if iteration%3:h.write(session+0x7668+i*36+10,h.read(identity,12))
            if iteration%11==0:
                for i in [0,1]:h.write(session+0x7668+i*36,b'\1');h.write(session+0x7668+i*36+10,h.read(session+0x1120+player*0x13c,12))
            h.write(session+0x111c,pack(mask));h.write(session+0x1118,pack(live if iteration%9 else 0))
            if mode=='refresh_peer_flag':h.write(session+0x54,pack([0,1,16,0xffffffff,0x80000000][iteration%5]))
            def run():
                if mode=='refresh_peer_flag':funcs[mode](h.memory,session)
                else:funcs[mode](h.memory,session,player if mode=='remove_player' else selected,scratch)
                assert h.read(scratch,4)==frames.get('argument_bytes',seed),(mode,iteration,'scratch')
                nw(scratch,seed)
            addr={'refresh_peer_flag':0x5a2e0,'remove_player':0x60200,'remove_peer':0x5fe20}[mode]
            regs={'refresh_peer_flag':dict(edx=session),'remove_player':dict(esi=session),'remove_peer':dict(eax=session,ebx=selected)}[mode]
            args=[player] if mode=='remove_player' else []
            try:h.call(mode,addr,regs,args,run)
            except Exception:
                print(mode,iteration,hex(h.u.reg_read(X.UC_X86_REG_EIP)));raise
    assert all(coverage.get(k) for k in ['remove_player','reservation_lookup','detach','memmove'])
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-removal-tests.json');a=p.parse_args();library=(ROOT/a.library).resolve();h=Harness(library)
    try:coverage=suite(h)
    finally:h.close()
    sources=['src/network_session_removal.c','include/halo2/network_session_removal.h','src/network_session.c','src/network_session_lifecycle.c','tests/network_session_removal_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),boundary_coverage=coverage,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='player/peer removal and peer flag refresh with actual reservation lookup, detach and original CRT memmove. Full memory, reused argument scratch, slot masks, count/revision wrapping, duplicate reservations, index shifts and last-peer removal. Valid peer membership bounds; no full admission or gameplay.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
