#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x53c30);a=h.table;b=a+0x8000;out=b+0x8000
    pack=lambda x:struct.pack('<I',x&0xffffffff)
    coverage={'success':0,'failure':0,'aliased_success':0}
    for name,address in [('a',0x59670),('b',0x596a0),('selected',0x53c30)]:
        fn=getattr(h.lib,'h2_network_game_session_'+name);fn.argtypes=[C.POINTER(Memory),C.c_uint32];fn.restype=C.c_uint8
        for case in range(1024):
            h.write(0x527364,pack(a));h.write(0x52736c,pack(b));h.write(a+0x741c,pack(case%4));h.write(b+0x741c,pack(case//4%4));h.write(out,rng.randbytes(4))
            h.write(0x527330,bytes([0 if case%7==0 else 255]));h.write(0x4c99b8,bytes([0 if case%11==0 else 2]));h.write(0x476fcc,bytes([0 if case%13==0 else 128]));h.write(0x4c9888,pack(0 if case%17==0 else 1));h.write(0x4c988c,pack([0,1,2,3,0xffffffff][case//8%5]))
            output=[0,out,a+0x741c,b+0x741c,0x527364,0x52736c,0x4c988c,0x527330][case//5%8]
            def run():
                result=fn(h.memory,output);coverage['success' if result else 'failure']+=1
                if result and output not in [0,out]:coverage['aliased_success']+=1
                return result
            h.call(name,address,dict(edx=output),[],run,255)
    assert all(coverage.values()),coverage
    return coverage

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-game-session-tests.json');a=p.parse_args();lib=(ROOT/a.library).resolve();h=Harness(lib)
    try:coverage=suite(h)
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    files=['src/network_game_session.c','include/halo2/network_game_session.h','tests/network_game_session_oracle.py']
    d=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(lib),comparisons=h.counts,coverage=coverage,source_hashes={f:H(ROOT/f) for f in files},scope='Original two session getters and selected-session dispatcher; actual engine callees, AL and full memory. All gates, selectors, optional null output, untouched failure output and aliases into session state/global pointers. Valid session pointers when gates allow access; no whole game activity query.')
    (ROOT/a.report).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
