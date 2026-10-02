#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x93590);packet=h.table;buffer=packet+0x1000;output=packet+0x1c00
    pack=h.lib.h2_network_packet_pack;pack.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;pack.restype=None
    unpack=h.lib.h2_network_packet_unpack;unpack.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;unpack.restype=C.c_uint8
    account=h.lib.h2_network_packet_accounted_size;account.argtypes=[C.POINTER(Memory),C.c_uint32];account.restype=C.c_uint32
    for i in range(192):
        h.write(packet,rng.randbytes(0x2000));kind=[0,1,2,3,4,0xffffffff][i%6]
        primary=[0,1,2,3,4,7,8,31,64,0x5ff,0x600][i%11];secondary=[0,1,3,4,7,0x1ff,0x200][i%7]
        destination=packet+0x24 if primary<=64 and i%3==0 else buffer
        h.write(packet,struct.pack('<I',kind));h.write(packet+0x1c,struct.pack('<I',primary));h.write(packet+0x620,struct.pack('<I',secondary))
        out=destination if i%13==0 else output
        h.call('pack',0x93590,dict(eax=packet,edx=destination,ebx=out),[],lambda:pack(h.memory,packet,destination,out))
    for i in range(384):
        h.write(packet,rng.randbytes(0x2000));kind=[0,1,2,3,4,0xffffffff][i%6]
        primary=[0,1,7,0x5ff,0x600,0x601,0xffff][i%7];secondary=[0,1,7,0x1ff,0x200,0x201][i//7%6]
        size=primary+secondary+2 if i%4 else [0,1,2,0x600,0x601,0x80000000,0xffffffff][i//4%7]
        source=packet+0x21 if i%11==0 else buffer
        h.write(packet,struct.pack('<I',kind));h.write(source,struct.pack('<H',primary))
        h.call('unpack',0x93610,dict(edx=packet,ecx=size),[source],lambda:unpack(h.memory,packet,size,source),255)
    for i in range(128):
        primary=[0,1,7,8,9,0x7ffffff9,0x7fffffff,0x80000000,0xfffffff9,0xffffffff][i%10]
        h.write(packet,struct.pack('<I',i%5));h.write(packet+0x1c,struct.pack('<I',primary));h.write(packet+0x620,struct.pack('<I',rng.getrandbits(32)))
        h.call('accounted_size',0x936c0,dict(edi=packet),[],lambda:account(h.memory,packet),0xffffffff)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-packet-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_packet.c','include/halo2/network_packet.h','tests/network_packet_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Unmodified original packet packing, unpacking and accounting instructions. Full persistent memory/returns, rejected lengths and partial metadata updates, overlap, both layouts and wrapped accounting. No socket transmission.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
