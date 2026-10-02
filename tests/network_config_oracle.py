#!/usr/bin/env python3
"""Persisted-state defaults and validation against untouched original x86."""
import argparse
import ctypes as C
import hashlib
import json
import random
import struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT, Memory, EXPECTED

BASE = 0x4cf970
RECORDS = BASE+0x1c
COUNT = 350
STRIDE = 0x68


def suite(h):
    lib = h.lib
    rng = random.Random(0x80660)
    for name, ret in [('defaults', None), ('validate', C.c_uint8)]:
        fn = getattr(lib, 'h2_network_config_'+name)
        fn.argtypes = [C.POINTER(Memory)]
        fn.restype = ret
    lib.h2_network_config_fields_valid.argtypes = [C.POINTER(Memory), C.c_uint32]
    lib.h2_network_config_fields_valid.restype = C.c_uint8

    def validate(expected=None):
        result = h.call('validate', 0x80660, {}, [],
                        lambda: lib.h2_network_config_validate(h.memory), 255)
        if expected is not None:
            assert result == expected
        return result

    for _ in range(16):
        h.write(BASE-4, rng.randbytes(0x8e54))
        h.call('defaults', 0x7f930, {}, [], lambda: lib.h2_network_config_defaults(h.memory))
        assert h.u32(BASE) == 8 and h.u32(BASE+8) == 0
        for i in range(COUNT):
            p = RECORDS+i*STRIDE
            assert h.read(p+0x56, 10) == b'\xff\0'+b'\xff'*8
        validate(1)

    # Exhaust each byte domain independently, including all negative signed-byte
    # encodings and the unusual accepted -1 value in the first five fields.
    for field in range(8):
        for value in range(256):
            data = bytearray(8)
            data[field] = value
            address = h.table+value%4
            h.write(address, bytes(data))
            expected = int(value == 255 or value < 18) if field < 4 else (
                int(value == 255 or value < 4) if field == 4 else
                int(value < [64,32,16][field-5]))
            result = h.call('fields', 0x153750, dict(edx=address), [],
                            lambda: lib.h2_network_config_fields_valid(h.memory,address), 255)
            assert result == expected

    def populate(n, chains=True):
        data = bytearray(0x1c+n*STRIDE)
        struct.pack_into('<III4I', data, 0, 8, rng.getrandbits(32), n,
                         *([0xffffffff]*4))
        for i in range(n):
            p = 0x1c+i*STRIDE
            data[p:p+4] = i.to_bytes(4, 'big')
            struct.pack_into('<I', data, p+8, 4*i)
            data[p+0x4c:p+0x54] = bytes([255,0,17,1,255,63,31,15])
            struct.pack_into('<4H', data, p+0x58, *([0xffff]*4))
        if n and chains:
            for head_offset, link_offset in [(12,0x5c),(20,0x58)]:
                order = list(range(n))
                rng.shuffle(order)
                struct.pack_into('<II', data, head_offset, order[0], order[-1])
                for j,index in enumerate(order):
                    struct.pack_into('<HH', data, 0x1c+index*STRIDE+link_offset,
                                     order[j-1] if j else 0xffff,
                                     order[j+1] if j+1<n else 0xffff)
        h.write(BASE,bytes(data))
        return bytes(data)

    for n in [0,1,2,7,31,32,33,349,350]:
        for chains in [False,True]:
            populate(n,chains)
            validate(1)

    baseline = populate(7)
    def reset(): h.write(BASE,baseline)
    for offset, values in [(0,[0,7,9,0xffffffff]), (8,[351,0x7fffffff,0x80000000,0xffffffff])]:
        for value in values:
            reset();h.write(BASE+offset,struct.pack('<I',value));validate(0)
    for offset in [12,16,20,24]:
        for value in [0xffffffff,7,0xfffffffe,0x80000000]:
            reset();h.write(BASE+offset,struct.pack('<I',value));validate(0)
    for index in [0,3,6]:
        for field in range(8):
            reset();h.write(RECORDS+index*STRIDE+0x4c+field,b'\xfe');validate(0)
        for value in [1,2,3,0xbad00000]:
            reset();h.write(RECORDS+index*STRIDE+8,struct.pack('<I',value));validate(0)
    for index in [1,3,6]:
        reset();h.write(RECORDS+index*STRIDE,baseline[0x1c+(index-1)*STRIDE:0x1c+(index-1)*STRIDE+12]);validate(0)
        reset();h.write(RECORDS+index*STRIDE,b'\0'*12);validate(0)
    # Corrupt links throughout both lists. Some mutations are equivalent to the
    # original value; the instruction oracle determines those outcomes.
    for index in range(7):
        for offset in [0x58,0x5a,0x5c,0x5e]:
            for value in [0,6,7,0x8000,0xfffe,0xffff]:
                reset();h.write(RECORDS+index*STRIDE+offset,struct.pack('<H',value));validate()
    for _ in range(160):
        n = rng.choice([1,2,7,32,350])
        populate(n)
        index = rng.randrange(n)
        offset = rng.choice([0,8,0x4c,0x50,0x58,0x5a,0x5c,0x5e])
        h.write(RECORDS+index*STRIDE+offset,rng.randbytes(2))
        validate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', default='build/libhalo2_engine.so')
    parser.add_argument('--report', default='analysis/network-config-tests.json')
    args = parser.parse_args()
    library = (ROOT/args.library).resolve()
    h = Harness(library)
    try:
        suite(h)
    finally:
        h.close()
    sources = ['src/network_config.c','tests/network_config_oracle.py','tests/hash_crc_oracle.py']
    report = dict(passed=True,xbe_sha256=EXPECTED,
                  library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                  comparisons=h.counts,total_comparisons=sum(h.counts.values()),
                  source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                  scope='Defaults, field validation, and full persisted-state validator with all original callees intact. Exhaustive individual byte domains, record ordering, bounds and linked-list mutations. Full mapped-memory and AL comparison. File loading and complete startup remain unrecovered.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
