#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x78090);o=h.table;config=o+0x100
    next_rate=h.lib.h2_network_observer_next_rate
    next_rate.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_float,C.c_uint8];next_rate.restype=C.c_float
    select=h.lib.h2_network_observer_select_rate
    select.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32,C.c_uint8,C.c_uint8];select.restype=C.c_float
    budget=h.lib.h2_network_observer_rate_budget
    budget.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint8,C.c_float];budget.restype=C.c_uint32
    limited=h.lib.h2_network_observer_rate_limited
    limited.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_float,C.c_uint8,C.c_uint8,C.c_uint8];limited.restype=C.c_uint8
    def w(a,v):h.write(a,struct.pack('<I',v&0xffffffff))
    def bits(f):return struct.unpack('<I',struct.pack('<f',f))[0]
    values=[0.0,-0.0,0.25,0.5,1.0,2.0,10.0,-1.0,1e30,float('inf'),float('-inf'),float('nan')]
    for case in range(768):
        h.write(o,rng.randbytes(0x400));w(o+16,config)
        h.write(0x485ac0,struct.pack('<H',[0,30,50,60,0xffff][case%5]))
        count=case%6;w(config+0x9c,count)
        for i in range(count):w(config+0xa0+i*4,bits(rng.choice(values)))
        for off in [0x108,0x10c]:w(config+off,rng.choice([0,1,100,0xffffffff,0x80000000,0x7fffffff]))
        w(config+0x110,bits(rng.choice(values)))
        alternate=case%3;capped=case//3%3;configured=case//9%3;baseline=case//27%3
        raw=rng.choice([0,1,100,100000,0xffffffff,0x80000000,0x7fffffff])
        native=[]
        h.call('select-rate',0x78090,dict(ecx=o),[raw,alternate,capped],
            lambda:native.append(select(h.memory,o,raw,alternate,capped)))
        original=h.u.reg_read(X.UC_X86_REG_XMM0)&0xffffffff
        assert bits(native[0])==original,(case,hex(bits(native[0])),hex(original))
        rate=rng.choice(values);packed=bits(rate)
        h.u.reg_write(X.UC_X86_REG_XMM3,packed)
        native.clear()
        h.call('next-rate',0x78210,{},[o,capped],lambda:native.append(next_rate(h.memory,o,rate,capped)))
        original=h.u.reg_read(X.UC_X86_REG_XMM0)&0xffffffff
        assert bits(native[0])==original,(case,'next-rate',hex(bits(native[0])),hex(original))
        h.call('rate-budget',0x78150,dict(eax=o,ecx=alternate),[packed],
            lambda:budget(h.memory,o,alternate,rate),mask=0xffffffff)
        h.u.reg_write(X.UC_X86_REG_XMM1,packed)
        h.call('rate-limited',0x78190,dict(ecx=configured),[o,baseline,capped],
            lambda:limited(h.memory,o,rate,configured,baseline,capped),mask=255)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/network-observer-rates-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_observer_rates.c','include/halo2/network_observer_rates.h','tests/network_observer_rates_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts,total_comparisons=sum(h.counts.values()),
        source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original rate selection/budget/limited instructions. Full memory, XMM0 bits, EAX/AL and stack purge. Both overhead modes, capped/uncapped tables, zero-count fallback, signed/wrapped budgets, zero/negative/infinite/NaN rates, default nearest-even conversion and overflow. No instruction hooks.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
