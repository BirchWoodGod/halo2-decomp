#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x79600);observer=h.table;config=observer+0x5000;outputs=observer+0x5200
    pack=lambda v:struct.pack('<I',v&0xffffffff)
    values=[0,1,0xffffffff,0x7fffffff,0x80000000,16777217,0x7fffff80,0x80000080]
    floats=[0,0x80000000,0x3f800000,0xbf800000,0x3f000000,0x42c80000,0x7f800000,0xff800000,0x7fc12345,0x4f000000,0x00800000,0x00000001]
    get=h.lib.h2_network_observer_get_metrics;get.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*6;get.restype=C.c_uint8
    apply=h.lib.h2_network_observer_apply_rate;apply.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32,C.c_float,C.c_uint32,C.c_uint32];apply.restype=None
    accepted=0
    for case in range(1024):
        index=[case%15,case%15,15,0xffffffff,0x80000000][case%5];entry=observer+0xa8+(case%15)*0x528
        h.write(entry,rng.randbytes(0x528));h.write(entry,pack(0 if case%7==0 else rng.getrandbits(32)|1));h.write(entry+0x48c,bytes([0 if case%11==0 else 255]));h.write(outputs,rng.randbytes(32))
        h.write(entry+0x358,pack(values[case%8]));h.write(entry+0x250,pack(values[case//8%8]));h.write(0x445420,pack(floats[case//64%12]))
        choices=[outputs,outputs+4,outputs+8,outputs+12,entry+0x4b0,entry+0x49c,entry+0x514,entry+0x358,entry+0x250,0x445420]
        out=[choices[(case//3+i*(case%4))%len(choices)] for i in range(4)]
        def run():
            nonlocal accepted
            result=get(h.memory,observer,index,*out);accepted+=bool(result);return result
        h.call('get_metrics',0x78a10,dict(ecx=index,edx=observer),out,run,255)
    for case in range(1024):
        index=case%15;entry=observer+0xa8+index*0x528
        h.write(entry,rng.randbytes(0x528));h.write(observer+16,pack(config));h.write(config+0x110,pack(floats[case//12%12]));h.write(0x485ac0,struct.pack('<H',[0,50,60,0xffff][case%4]))
        for i,off in enumerate([0x48d,0x48e,0x490]):h.write(entry+off,bytes([[0,1,2,255][case//(4**i)%4]]))
        bits=floats[case%12];rate=struct.unpack('<f',pack(bits))[0];budget=rng.getrandbits(32);burst=rng.getrandbits(32)
        h.u.reg_write(X.UC_X86_REG_XMM5,bits)
        h.call('apply_rate',0x79600,dict(ecx=observer,eax=index),[budget,burst],lambda:apply(h.memory,observer,index,rate,budget,burst))
    assert accepted>0
    return accepted

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-observer-metrics-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:accepted=suite(h)
    finally:h.close()
    sources=['src/network_observer_metrics.c','include/halo2/network_observer_metrics.h','src/network_observer_rates.c','tests/network_observer_metrics_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest(),engine_library_sha256=hashlib.sha256((lib.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),comparisons=h.counts,accepted_queries=accepted,source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},scope='Original metrics getter and rate setter with actual rate-limit helper. Full memory and AL; invalid indexes, absent state/metrics, output aliases including input fields and scale constant, signed conversions, overflow, zero divisors, infinities/quiet NaNs/subnormals and noncanonical boolean flags. Default floating environment only.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
