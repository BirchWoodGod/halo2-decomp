#!/usr/bin/env python3
"""Session storage constructor with no replaced calls; observer/session sequence."""
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations

def suite(h):
    lib=h.lib;rng=random.Random(0x59ad0);state=h.table;observer=state+0x10000;registry=observer+0x1000
    lib.h2_network_session_storage_initialize.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*7;lib.h2_network_session_storage_initialize.restype=C.c_uint8
    for repeat in range(10):
        for index in [0,1,2,14]:
            target=state+repeat%4;h.write(target,rng.randbytes(0x78b8));h.write(observer,rng.randbytes(0x400));h.write(registry,rng.randbytes(64))
            before=h.read(target,0x78b8);kind,dependency,owner=[rng.getrandbits(32) for _ in range(3)]
            h.call('session_initialize',0x59ad0,dict(eax=registry,edx=target,ecx=observer),[index,kind,dependency,owner],lambda:lib.h2_network_session_storage_initialize(h.memory,registry,target,observer,index,kind,dependency,owner),255)
            assert h.u32(registry+index*4)==target
            assert h.u32(observer+index*36+0x14)==target
            assert h.read(target,4)==before[:4] and h.read(target+0x78ad,11)==before[0x78ad:]
    # Original startup addresses and the three observed argument combinations.
    lib.h2_network_state_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*5;lib.h2_network_state_initialize.restype=C.c_uint8
    ops=Operations();observer=0x5291a0;registry=0x52e0e8;state=0x52e0f8;config=0x4cf4e0
    h.write(observer,rng.randbytes(0x4f40));h.write(state,rng.randbytes(3*0x78b8));h.write(registry,bytes(12))
    h.write(0x510548,struct.pack('<II',1,1234));h.write(config+0xf8,struct.pack('<I',2000))
    h.call('integrated_observer_initialize',0x75970,dict(esi=observer,eax=0x528000,edx=0x528b28,ecx=0x529188),[config],lambda:lib.h2_network_state_initialize(h.memory,C.byref(ops),observer,0x528000,0x528b28,0x529188,config),255)
    for index,kind,dependency in [(0,1,0),(1,1,1),(2,2,2)]:
        target=state+index*0x78b8;owner=0x528b28
        h.call('integrated_session_initialize',0x59ad0,dict(eax=registry,edx=target,ecx=observer),[index,kind,dependency,owner],lambda:lib.h2_network_session_storage_initialize(h.memory,registry,target,observer,index,kind,dependency,owner),255)
    assert [h.u32(registry+i*4) for i in range(3)]==[state+i*0x78b8 for i in range(3)]
    state=h.table;identity=state+0x9000
    guard=lib.h2_network_session_shutdown_guard;guard.argtypes=[C.POINTER(Memory),C.c_uint32];guard.restype=C.c_uint8
    find=lib.h2_network_session_find_peer;find.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];find.restype=C.c_uint32
    capacity=lib.h2_network_session_capacity_exceeded;capacity.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;capacity.restype=C.c_uint8
    for value in list(range(12))+[0x7fffffff,0x80000000,0xffffffff]:
        for flag in range(256) if value in [7,8] else [0,1,2,127,128,255]:
            h.write(state+0x741c,struct.pack('<IB',value,flag))
            h.call('shutdown_guard',0x58d90,dict(edx=state),[],lambda:guard(h.memory,state),255)
    for count in [0,1,3,16,0x80000000,0xffffffff]:
        for mode in range(5):
            h.write(state,rng.randbytes(0x78b8));h.write(identity,rng.randbytes(36))
            h.write(state+0x741c,struct.pack('<I',0 if mode==0 else 5))
            h.write(state+0x4c,struct.pack('<I',0xffffffff if mode==1 else 0))
            h.write(state+0x54,struct.pack('<I',count))
            if 0<count<=16 and mode>=2:
                index=[0,count//2,count-1][mode-2]
                h.write(state+0x58+index*0x10c,h.read(identity,36))
                if mode==4:h.write(state+0x58,h.read(identity,36)) # first duplicate wins
            h.call('find_peer',0x5f760,dict(ecx=state),[identity],lambda:find(h.memory,state,identity),0xffffffff)
    for byte in range(36):
        h.write(state+0x741c,struct.pack('<I',5));h.write(state+0x4c,struct.pack('<I',0));h.write(state+0x54,struct.pack('<I',1))
        data=rng.randbytes(36);h.write(identity,data);changed=bytearray(data);changed[byte]^=0xff;h.write(state+0x58,bytes(changed))
        h.call('find_peer_mismatch',0x5f760,dict(ecx=state),[identity],lambda:find(h.memory,state,identity),0xffffffff)
    edges=[0,1,2,0x7ffffffe,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]
    for iteration in range(480):
        value=([0,1,2,3,4,5,6,7,8,9,0x7fffffff,0x80000000,0xffffffff][iteration%13] if iteration<160 else 5)
        counts=[rng.choice(edges) if iteration<320 else rng.getrandbits(32) for _ in range(6)]
        current_peers,current_players,limit_peers,limit_players,peers,players=counts
        h.write(state+0x741c,struct.pack('<I',value));h.write(state+0x54,struct.pack('<I',current_peers));h.write(state+0x1118,struct.pack('<I',current_players));h.write(state+0x4990,struct.pack('<II',limit_peers,limit_players))
        h.call('capacity_exceeded',0x5af70,dict(ecx=state),[peers,players],lambda:capacity(h.memory,state,peers,players),255)

    reservation=lib.h2_network_session_find_reservation;reservation.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;reservation.restype=C.c_uint8
    reserved_capacity=lib.h2_network_session_reservation_capacity;reserved_capacity.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32,C.c_uint8,C.c_uint32];reserved_capacity.restype=C.c_uint8
    status=lib.h2_network_session_request_status;status.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];status.restype=C.c_uint32
    request=state+0x9000;output=state+0x9400
    def reservations():
        h.write(state,rng.randbytes(0x78b8));h.write(request,rng.randbytes(0x400))
        for i in range(16):
            h.write(state+0x7668+i*36,bytes([rng.choice([0,1,255]),rng.choice([0,1,128])]))
    for index in range(-1,16):
        for mode in range(4):
            reservations();h.write(output,struct.pack('<I',0xdeadbeef))
            if index>=0:
                entry=state+0x7668+index*36;h.write(entry,b'\1');h.write(entry+10,h.read(request+4,12))
                if mode==3:h.write(state+0x7668,b'\xff');h.write(state+0x7672,h.read(request+4,12))
            destination=[0,output,request+4,output][mode]
            h.call('find_reservation',0x62f40,dict(edx=state),[request+4,destination],lambda:reservation(h.memory,state,request+4,destination),255)
    for iteration in range(160):
        reservations();count=[0,1,3,16,0xffffffff,0x80000000][iteration%6];skip=[0,1,255][iteration%3]
        h.write(state+0x1118,struct.pack('<I',rng.choice(edges)));h.write(state+0x4994,struct.pack('<I',rng.choice(edges)))
        if count<=16:
            for i in range(count):
                entry=state+0x7668+(i%4)*36;h.write(entry,b'\1');h.write(request+4+i*12,h.read(entry+10,12))
        h.call('reservation_capacity',0x5afc0,dict(ebx=state,ecx=request+4,eax=skip),[count],lambda:reserved_capacity(h.memory,state,request+4,skip,count),255)
    for iteration in range(288):
        reservations();value=[0,4,5,6,7,8,9,0xffffffff][iteration%8]
        h.write(state+0x741c,struct.pack('<I',value));h.write(state+0x498c,struct.pack('<I',[0,1,2,0xffffffff][iteration//8%4]))
        h.write(state+0x4c,struct.pack('<I',0));h.write(state+0x54,struct.pack('<I',2));h.write(state+0x1118,struct.pack('<I',iteration%7));h.write(state+0x4990,struct.pack('<II',3,iteration%9))
        count=iteration%5;h.write(request,struct.pack('<I',count));h.write(request+0x14c,bytes([iteration%2]))
        if iteration//32%3==1:h.write(state+0x58,h.read(request+0x188,36))
        if iteration//32%3==2:
            for i in range(count):
                entry=state+0x7668+i*36;h.write(entry,b'\1\0');h.write(entry+10,h.read(request+4+i*12,12))
        h.call('request_status',0x62fe0,dict(eax=state,edi=request),[],lambda:status(h.memory,state,request),0xffffffff)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-session-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['include/halo2/network_session.h','src/network_session.c','tests/network_session_oracle.py','tests/hash_crc_oracle.py']},scope='Constructor, shutdown guard, peer and reservation lookups, capacity and request admission checks: unmodified original instructions; signed overflow, invalid states, all state-7/8 flag bytes, first duplicate and every identity byte mismatch.  full mapped-memory comparisons and observed three-session sequence with observer initializer. Timing override avoids SDK calls. Not the complete session state machine or network startup.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
