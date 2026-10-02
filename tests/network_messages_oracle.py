#!/usr/bin/env python3
"""Nine descriptor registration routines, original x86 with no replaced calls."""
import argparse,ctypes as C,hashlib,json,random
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
FUNCTIONS=[('discovery',0xac800),('connection',0xacb10),('session',0xadab0),('membership',0xaf680),('parameters',0xb2220),('simulation',0xb2680),('synchronous',0xb2b30),('results',0xb2cc0),('test',0xb2de0)]
def suite(h):
    rng=random.Random(0xac800)
    for name,address in FUNCTIONS:
        f=getattr(h.lib,'h2_messages_register_'+name);f.argtypes=[C.POINTER(Memory),C.c_uint32];f.restype=None
    for iteration in range(20):
        table=0x528588 if iteration==0 else h.table+iteration%4
        baseline=rng.randbytes(0x5a0)
        h.write(table,baseline)
        for name,address in FUNCTIONS:
            h.call(name,address,dict(eax=table),[],lambda:getattr(h.lib,'h2_messages_register_'+name)(h.memory,table))
        assert all(h.read(table+i*32,1)==b'\1' for i in range(45))
        assert all(h.read(table+i*32+1,3)==baseline[i*32+1:i*32+4] for i in range(45))
        # Re-registration on already populated state must preserve all bytes.
        before=h.read(table,0x5a0)
        for name,address in reversed(FUNCTIONS):
            h.call(name,address,dict(eax=table),[],lambda:getattr(h.lib,'h2_messages_register_'+name)(h.memory,table))
        assert h.read(table,0x5a0)==before
    # Independent bounds/flag check for the variable-sized synchronous gamestate descriptor.
    assert h.u32(table+42*32+8)==1
    assert h.u32(table+42*32+12)==8 and h.u32(table+42*32+16)==0xffff

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-message-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/network_messages.c','config/message_descriptors.json','tests/network_messages_oracle.py','tests/hash_crc_oracle.py']},scope='Nine registration routines, 45 descriptors. Original instructions unmodified, full mapped-memory comparison. Does not implement codecs or networking.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
