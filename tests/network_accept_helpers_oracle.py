#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x785d0);a=h.table;b=a+0x100;c=a+0x400
    flags=h.lib.h2_network_connection_flags_valid;flags.argtypes=[C.c_uint32];flags.restype=C.c_uint8
    copy=h.lib.h2_network_connection_copy_address;copy.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];copy.restype=C.c_uint8
    equal=h.lib.h2_network_address_equal;equal.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32,C.c_uint8];equal.restype=C.c_uint8
    for low in range(256):
        for high in [0,0x100,0x80000000,0xffffff00]:
            value=high|low
            h.call('flags',0x880b0,dict(ecx=value),[],lambda:flags(value),mask=255)
    for case in range(768):
        h.write(a,rng.randbytes(0x800))
        state=[0,1,2,3,4,5,0xffffffff,0x80000000][case%8]
        h.write(c+0x54,struct.pack('<I',state));out=c+0x70+[-7,0,1,4,8,12,16,64][case//8%8]
        h.call('copy-address',0x75930,dict(eax=c,ecx=out),[],lambda:copy(h.memory,c,out),mask=255)
        # Keep backing buffers valid for extended positive address lengths too.
        length=rng.choice([0,1,4,6,16,20,24,32,0xffff,0x8000])
        other=length if case%4 else rng.choice([0,1,4,16,0xffff])
        raw=rng.randbytes(64);h.write(a,raw);h.write(b,raw)
        h.write(a+18,struct.pack('<H',length));h.write(b+18,struct.pack('<H',other))
        if case%3==0:h.write(b+case%16,bytes([h.read(b+case%16,1)[0]^1]))
        if case%5==0:h.write(b+16,b'\x12\x34')
        second=a if case%7==0 else b;port=case%3
        h.call('address-equal',0x7af80,dict(ebx=a),[second,port],lambda:equal(h.memory,a,second,port),mask=255)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_accept_helpers_preview.so');p.add_argument('--report',default='analysis/network-accept-helpers-preview.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_accept_helpers.c','include/halo2/network_accept_helpers.h','tests/network_accept_helpers_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original flag validation, connection address copy and address comparison instructions. Full memory and AL; all256 low flag combinations with high-bit rejection, signed lengths, port gating, aliases and overlapping ordered DWORD copies. No instruction hooks.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
