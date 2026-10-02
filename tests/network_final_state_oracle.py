#!/usr/bin/env python3
"""Final network startup state resets, with every original callee intact."""
import argparse
import ctypes as C
import hashlib
import json
import random
from hash_crc_oracle import Harness
from data_array_oracle import ROOT, Memory, EXPECTED


def suite(h):
    lib = h.lib
    rng = random.Random(0x53210)
    for name in ['slot', 'vector']:
        fn = getattr(lib, 'h2_network_'+name+'_state_initialize')
        fn.argtypes = [C.POINTER(Memory), C.c_uint32]
        fn.restype = None
    lib.h2_network_final_state_initialize.argtypes = [C.POINTER(Memory)]
    lib.h2_network_final_state_initialize.restype = None
    for i in range(48):
        state = h.table+i%4
        h.write(h.table, rng.randbytes(0x1720))
        h.call('slot_state', 0x56080, {}, [state],
               lambda: lib.h2_network_slot_state_initialize(h.memory, state))
        for j in range(16):
            assert h.u32(state+j*0x170+0x10) == j
            assert h.read(state+j*0x170+4, 1) == b'\x01'
        h.write(h.table, rng.randbytes(0x230))
        h.call('vector_state', 0x56ae0, dict(edx=state), [],
               lambda: lib.h2_network_vector_state_initialize(h.memory, state))
        assert h.u32(state+0x18c) == 0xfffffc18
        assert h.u32(state+0x188) == 0xffffffb0
        h.write(0x4c9874, rng.randbytes(0x14c))
        h.write(0x5259b4, rng.randbytes(0x1970))
        h.call('final_state', 0x53210, {}, [],
               lambda: lib.h2_network_final_state_initialize(h.memory))
        assert h.u32(0x4c9878) == 0xffffffff
        for flag in [0x5259b8, 0x527104, 0x4c99b8, 0x525a00, 0x527108]:
            assert h.read(flag, 1) == b'\x01'
        for j in range(16):
            assert h.u32(0x525a10+j*0x170) == j


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', default='build/libhalo2_engine.so')
    parser.add_argument('--report', default='analysis/network-final-state-tests.json')
    args = parser.parse_args()
    library = (ROOT/args.library).resolve()
    h = Harness(library)
    try:
        suite(h)
    finally:
        h.close()
    sources = ['src/network_final_state.c', 'tests/network_final_state_oracle.py',
               'tests/hash_crc_oracle.py']
    report = dict(passed=True, xbe_sha256=EXPECTED,
                  library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                  comparisons=h.counts, total_comparisons=sum(h.counts.values()),
                  source_hashes={s: hashlib.sha256((ROOT/s).read_bytes()).hexdigest()
                                 for s in sources},
                  scope='Three state initialization routines, including original callees; full mapped-memory comparisons with randomized previous contents and alignment. No substituted calls. Complete network startup remains unfinished.')
    (ROOT/args.report).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
