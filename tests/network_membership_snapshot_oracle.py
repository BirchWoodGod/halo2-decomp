#!/usr/bin/env python3
"""Membership snapshot through original peer changes and CRT string bodies."""
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x60400);session=h.table;current=session+0x8000;baseline=session+0xb000;output=session+0xe000
    fn=h.lib.h2_network_membership_snapshot;fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4;fn.restype=None
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    counts={'peer_entries':0,'player_entries':0}
    for case in range(2048):
        h.write(session,rng.randbytes(0x40));data=bytearray(rng.randbytes(0x2494));n=[0,1,2,8,15,16][case%6];data[8:12]=pack(n)
        for i in range(16):
            p=12+i*0x10c;data[p:p+36]=pack(i+1)*9
            for off,units in [(0x28,16),(0x48,32)]:
                pos=[None,0,1,units-1][case//6%4]
                if pos is not None:data[p+off+pos*2:p+off+pos*2+2]=bytes(2)
        mask=[0,1,0x8000,0x5555,0xffff][case//6%5] if n else 0
        data[0x10d0:0x10d4]=pack(mask)
        for i in range(16):
            p=0x10d4+i*0x13c;data[p+12:p+16]=pack(i%max(n,1));data[p+20:p+24]=pack(0xffffffff if (case+i)%3==0 else i)
        other=bytearray(data);mode=case//30%6
        if mode==1 and n:
            # Reverse peer order and adjust baseline player ownership.
            for i in range(n):other[12+i*0x10c:12+(i+1)*0x10c]=data[12+(n-1-i)*0x10c:12+(n-i)*0x10c]
            for i in range(16):
                p=0x10d4+i*0x13c;other[p+12:p+16]=pack(n-1-i%n)
        elif mode==2 and n:
            other[12:48]=b'\xee'*36
        elif mode==3:
            for _ in range(12):
                if n:other[12+rng.randrange(n)*0x10c+0x24+rng.randrange(0xcc)]^=0xff
            other[0x10d0:0x10d4]=pack(mask^0x8001 if n else 0)
        elif mode==4:
            for i in range(16):
                p=0x10d4+i*0x13c;other[p+24+(case+i)%0x90]^=0xff
            other[4:8]=pack(case)
        if case>=1024:
            old_count=(case//7)%17;other[8:12]=pack(old_count)
            if not old_count:other[0x10d0:0x10d4]=pack(0)
            for i in range(16):
                p=0x10d4+i*0x13c;other[p+12:p+16]=pack(i%max(old_count,1))
            # Matching scans retain the last match in each direction, including duplicates.
            if case%3!=0:
                for i in range(n):data[12+i*0x10c:48+i*0x10c]=pack(1)*9
                for i in range(old_count):other[12+i*0x10c:48+i*0x10c]=pack(1)*9
            if case%5==0:
                for i in range(16):
                    p=0x10d4+i*0x13c;other[p+16:p+20]=pack(i)
            if case%5==1:
                for i in range(16):
                    p=0x10d4+i*0x13c;other[p:p+12]=bytes(12)
            if case%5==2:
                for i in range(16):
                    p=0x10d4+i*0x13c;other[p+0xa8+(i%0x90)]^=0xff
            if case%5==3:
                for i in range(16):
                    p=0x10d4+i*0x13c;other[p+0x138:p+0x13c]=pack(i)
        h.write(current,bytes(data));h.write(baseline,bytes(other));h.write(output,rng.randbytes(0x489c))
        b=0 if case%7==0 else current if case%11==0 else baseline
        h.call('membership_snapshot',0x60400,dict(eax=session),[current,b,output],lambda:fn(h.memory,session,current,b,output),None)
        peers,players=struct.unpack('<HH',h.read(output+16,4));counts['peer_entries']+=peers;counts['player_entries']+=players
    assert all(counts.values());return counts

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-membership-snapshot-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources=['src/network_membership_snapshot.c','include/halo2/network_membership_snapshot.h','src/network_peer_changes.c','include/halo2/network_peer_changes.h','tests/network_membership_snapshot_oracle.py','tests/hash_crc_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=sha(lib),engine_library_sha256=sha(lib.parent/'libhalo2_engine.so'),comparisons=h.counts,total_comparisons=sum(h.counts.values()),coverage=coverage,source_hashes={s:sha(ROOT/s) for s in sources},scope='Full memory/ret12; original peer-change and CRT callees intact. Null/equal/current-aliased baselines, 0..16 bounded peer counts, peer permutations/removal/addition, unequal counts/duplicate identities, player masks/ownership changes and payload mutations. Output disjoint. Not full membership broadcast.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
