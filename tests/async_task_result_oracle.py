#!/usr/bin/env python3
"""Compare the task result decoder with original XBE instructions."""
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT, Memory, EXPECTED

def suite(h):
    rng = random.Random(0x7b7b0)
    pool = h.table
    entries = pool + 0x100
    record = pool + 0x400
    fn = h.lib.h2_async_task_result
    fn.argtypes = [C.POINTER(Memory)] + [C.c_uint32] * 3
    fn.restype = C.c_uint8
    # All flag bytes, disjoint output and overlapping writes on either side.
    for flags in range(256):
        for offset in [0x100, -17, 0, 7, 19]:
            h.write(pool, rng.randbytes(0x800))
            salt = rng.choice([1, 0x7fff, 0x8000, 0xffff])
            stride = rng.choice([8, 12, 16])
            index = rng.choice([0, 1, 63, 0xffffffff, 0x80000000])
            h.write(0x4cf8d4, b'\x01')
            h.write(0x4cf8d8, struct.pack('<I', pool))
            for off, value in [(0x24, stride), (0x38, 3), (0x44, entries)]:
                h.write(pool + off, struct.pack('<I', value))
            h.write(entries + stride, struct.pack('<HHI', salt, 0,
                    (record - 8 - index * 24) & 0xffffffff))
            h.write(record, bytes([flags]))
            handle = salt << 16 | 1
            out = record + offset
            h.call('flags-and-aliases', 0x7b7b0, dict(eax=handle, edi=out), [index],
                   lambda: fn(h.memory, handle, index, out), mask=255)
    # Invalid handles and signed pool limits must leave the output untouched.
    for enabled, limit, salt, handle in [
        (0, 3, 0x8002, 0x80020001), (1, 0, 0x8002, 0x80020001),
        (1, 0xffffffff, 0x8002, 0x80020001), (1, 0x80000000, 0x8002, 0x80020001),
        (1, 3, 0, 0x80020001), (1, 3, 0x8003, 0x80020001),
        (1, 3, 0xffff, 0xffffffff), (1, 3, 0x8002, 0x80020003)]:
        h.write(0x4cf8d4, bytes([enabled]))
        h.write(pool + 0x38, struct.pack('<I', limit))
        h.write(entries + stride, struct.pack('<H', salt))
        h.call('invalid-handle', 0x7b7b0, dict(eax=handle, edi=out), [0],
               lambda: fn(h.memory, handle, 0, out), mask=255)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--library', default='build/libhalo2_engine.so')
    p.add_argument('--report', default='analysis/async-task-result-tests.json')
    args = p.parse_args()
    library = (ROOT / args.library).resolve()
    h = Harness(library)
    try:
        suite(h)
    finally:
        h.close()
    sources = ['src/async_task_result.c', 'include/halo2/async_task_result.h',
               'tests/async_task_result_oracle.py', 'tests/hash_crc_oracle.py']
    report = dict(passed=True, xbe_sha256=EXPECTED,
        library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        engine_library_sha256=hashlib.sha256((library.parent/'libhalo2_engine.so').read_bytes()).hexdigest(),
        comparisons=h.counts, total_comparisons=sum(h.counts.values()),
        source_hashes={s: hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
        scope='Original XBE task-result instructions, AL and full guest-memory comparison; all flags, signed salts/limits, wrapped result indices, overlapping output. No SDK hooks or service emulation.')
    (ROOT/args.report).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
