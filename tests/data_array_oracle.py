#!/usr/bin/env python3
"""Differential tests: native recovered C versus unmodified retail XBE x86.

The oracle executes the original routines and their original strncpy, with no
replacement hooks. Tests compare the entire heap arena (including canaries),
specified return values, and stack cleanup after every operation. This proves
the sampled behavior of these routines, not a playable game or full decompilation.
"""
import argparse
import collections
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from vendor.xbe_parse import XbeParser
from prepare import EXPECTED
import unicorn as U
from unicorn import x86_const as X

BASE, HEAP_SIZE = 0x1000000, 0x100000
STACK, STOP = 0x2000000, 0x3000000
NAME, ARRAY, ITERATOR = BASE + 0x40, BASE + 0x101, BASE + 0xc0
NONE = 0xffffffff
REGS = {n: getattr(X, 'UC_X86_REG_' + n.upper()) for n in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']}

# One ABI catalog drives Ghidra annotations and the original-machine-code caller.
CATALOG = json.loads((ROOT/'config/data_array_abi.json').read_text())
assert CATALOG['xbe_sha256'] == EXPECTED
ABI = {f['name'].removeprefix('h2_data_'): (int(f['address'],16),
       [p['storage'] for p in f['parameters']], f['stack_purge'], f['returns'] != 'void')
       for f in CATALOG['functions']}

class Memory(C.Structure):
    _fields_ = [('bytes', C.POINTER(C.c_uint8)), ('base', C.c_uint32), ('size', C.c_size_t)]

class Oracle:
    def __init__(self, library):
        data = (ROOT / 'default.xbe').read_bytes()
        assert hashlib.sha256(data).hexdigest() == EXPECTED, 'Wrong executable'
        meta = XbeParser(data, 'default.xbe').parse()
        self.uc = u = U.Uc(U.UC_ARCH_X86, U.UC_MODE_32)
        size = (meta.size_of_image + 0xfff) & ~0xfff
        u.mem_map(meta.base_address, size)
        u.mem_write(meta.base_address, data[:meta.size_of_headers])
        for section in meta.sections:
            u.mem_write(section.virtual_address, data[section.raw_address:section.raw_address+section.raw_size])
        u.mem_protect(meta.base_address, size, U.UC_PROT_READ | U.UC_PROT_EXEC)
        u.mem_map(BASE, HEAP_SIZE, U.UC_PROT_READ | U.UC_PROT_WRITE)
        u.mem_map(STACK, 0x10000, U.UC_PROT_READ | U.UC_PROT_WRITE)
        u.mem_map(STOP, 0x1000, U.UC_PROT_READ | U.UC_PROT_EXEC)
        self.buf = (C.c_uint8 * HEAP_SIZE)()
        self.mem = Memory(self.buf, BASE, HEAP_SIZE)
        self.lib = C.CDLL(str(library))
        for name, (_, locations, _, returns) in ABI.items():
            f = getattr(self.lib, 'h2_data_' + name)
            f.argtypes = [C.POINTER(Memory)] + [C.c_uint32] * len(locations)
            f.restype = C.c_uint32 if returns else None
        self.counts = collections.Counter()
        self.visited = set()
        self.span = HEAP_SIZE
        u.hook_add(U.UC_HOOK_MEM_WRITE, self.check_write)
        u.hook_add(U.UC_HOOK_BLOCK, lambda _u, addr, size, _: self.visited.add(addr))

    def check_write(self, uc, access, addr, size, value, _):
        assert BASE <= addr and addr + size <= BASE + self.span or STACK <= addr and addr + size <= STACK + 0x10000, hex(addr)

    def reset(self, capacity, stride, align=0, name=b'actors', flag=0, offset=0x101):
        self.array = BASE + offset
        self.capacity, self.stride = capacity, stride
        self.span = (offset + 0x4c + (1 << align) + capacity * stride + ((capacity+31)//32)*4 + 0x1000 + 0xfff) & ~0xfff
        assert self.span <= HEAP_SIZE
        self.mem.size = self.span
        initial = bytes([0xa5]) * self.span
        C.memmove(self.buf, initial, self.span)
        self.uc.mem_write(BASE, initial)
        self.write(NAME, name + b'\0')
        self.call('init', self.array, align, stride, capacity, NAME, 0x34567890)
        self.write(self.array + 0x2a, bytes([flag]))

    def write(self, addr, data):
        assert BASE <= addr and addr + len(data) <= BASE + self.span
        C.memmove(C.addressof(self.buf) + addr - BASE, data, len(data))
        self.uc.mem_write(addr, data)

    def u32(self, addr):
        return struct.unpack_from('<I', self.buf, addr - BASE)[0]

    def call(self, name, *args):
        entry, locations, purge, returns = ABI[name]
        assert len(args) == len(locations)
        u = self.uc
        for i, reg in enumerate(REGS.values()): u.reg_write(reg, 0x76540000 + i)
        u.reg_write(X.UC_X86_REG_EFLAGS, 2)  # Xbox ABI expects DF clear.
        esp = STACK + 0x8000
        stack = [STOP]
        for loc, arg in zip(locations, args):
            if loc.startswith('stack:'):
                assert int(loc.split(':')[1]) == 4*len(stack)
                stack.append(arg & NONE)
            else: u.reg_write(REGS[loc], arg & NONE)
        u.mem_write(esp, struct.pack('<' + 'I'*len(stack), *stack))
        u.reg_write(X.UC_X86_REG_ESP, esp)
        u.emu_start(entry, STOP, timeout=5_000_000, count=2_000_000)
        assert u.reg_read(X.UC_X86_REG_EIP) == STOP, (name, 'failed to return', hex(u.reg_read(X.UC_X86_REG_EIP)))
        assert u.reg_read(X.UC_X86_REG_ESP) == esp + 4 + purge, (name, 'stack cleanup')
        expected_return = u.reg_read(X.UC_X86_REG_EAX)
        result = getattr(self.lib, 'h2_data_' + name)(C.byref(self.mem), *args)
        expected = bytes(u.mem_read(BASE, self.span))
        actual = bytes(self.buf[:self.span])
        if expected != actual:
            at = next(i for i, (a,b) in enumerate(zip(expected,actual)) if a != b)
            raise AssertionError((name, [hex(a) for a in args], hex(BASE+at),
                                  'xbe', expected[at:at+16].hex(), 'native', actual[at:at+16].hex()))
        if returns: assert result == expected_return, (name, hex(result), hex(expected_return))
        self.counts[name] += 1
        return result

def suite(o):
    # Real engine pool sizes, empty/singleton and bitmap boundaries; deliberately
    # unaligned headers/strides exercise guest layout rather than host structs.
    for capacity, stride in [(0,2),(1,3),(10,0x8c),(31,7),(32,9),(33,5),(40,0xd4),(65,13),(256,0x888)]:
        for align in [0, 2, 4]:
            o.reset(capacity, stride, align)
            a = o.array
            o.call('activate', a)
            handles = [o.call('new', a) for _ in range(min(capacity, 4))]
            for h in handles: o.call('get', a, h)
            o.call('clear', a)
    # Verify the header helper separately, including name truncation/padding.
    for name in [b'', b'a', b'ab', b'x'*31, b'y'*32, b'z'*70]:
        o.reset(5, 7, name=name)
        o.call('header_init', o.array, NAME, 5, 7, 3, 0x12345678, BASE+0x900)
    # 16-bit index boundary, non-word element sizes, and live bitmap tail bits.
    o.reset(65535, 3, align=3)
    a = o.array
    o.call('activate', a)
    h = o.call('new_at', a, 65534)
    assert h != NONE
    o.call('get', a, h)
    o.call('get', a, h ^ 0x10000)  # stale salt
    o.call('new_at', a, 65535)
    o.call('find', a, 65504)
    o.call('delete', a, h)
    # Explicit-handle creation accepts a zero salt in the XBE, although ordinary
    # engine allocation never generates one. Preserve that observable behavior.
    o.reset(2, 5)
    a = o.array
    o.call('activate', a)
    assert o.call('new_handle', a, 0) == 0
    assert o.call('get', a, 0) == 0
    assert o.call('find', a, 0) == 0
    o.call('rebuild', a, 2, o.u32(a+0x44))
    assert o.u32(a+0x3c) == 0
    # x86 masks the shift count but stores the low byte of the original count.
    o.call('init', a, 32, 5, 2, NAME, 0x34567890)
    rng = random.Random(0x4d530064)
    for case in range(32):
        capacity = rng.choice([1,2,10,31,32,33,40,64,65,97])
        o.reset(capacity, rng.choice([2,3,7,16,31,0x8c,0xd4]), rng.randrange(5),
                name=rng.choice([b'', b'a', b'actors', b'command scripts']), flag=8*(case%2))
        a = o.array
        o.call('activate', a)
        live = {}
        # Force generation counter rollover through FFFE -> 8000.
        o.write(a+0x40, struct.pack('<H', 0xfffe))
        for step in range(160):
            op = rng.randrange(8)
            if op < 2:
                h = o.call('new', a)
                if h != NONE: live[h & 0xffff] = h
            elif op == 2 and live:
                i = rng.choice(list(live)); h = live.pop(i)
                o.call('delete', a, h)
                assert o.call('get', a, h) == 0
            elif op == 3:
                i = rng.randrange(capacity + 2)
                h = o.call('new_at', a, i)
                if h != NONE: live[i] = h
            elif op == 4:
                i = rng.randrange(capacity + 2)
                h = o.call('new_handle', a, (rng.randrange(0x8000,0xffff)<<16) | i)
                if h != NONE: live[i] = h
            elif op == 5:
                i = rng.choice([NONE, 0x80000000, rng.randrange(capacity+2)])
                o.call('get_index', a, i)
                o.call('find', a, i)
                o.call('get', a, rng.getrandbits(32))
            elif op == 6:
                o.call('rebuild', a, capacity, o.u32(a+0x44))
            elif live:
                i = rng.choice(list(live))
                o.call('get', a, live[i]); o.call('handle', a, i)
                o.call('next', a, live[i])
            assert o.u32(a+0x3c) == len(live)
        # Traverse both iterator APIs and verify exhaustion.
        o.write(ITERATOR, struct.pack('<III', a, NONE, NONE))
        found = []
        for _ in range(capacity+1):
            p = o.call('iterator_next', ITERATOR)
            if not p: break
            found.append(o.u32(ITERATOR+8))
        assert found == sorted(live)
        h = NONE; found = []
        for _ in range(capacity+1):
            h = o.call('next', a, h)
            if h == NONE: break
            found.append(h & 0xffff)
        assert found == sorted(live)
        o.call('clear', a)
        # Direct helper does not reserve a bitmap bit; test that behavior too.
        o.call('slot_init', a, o.u32(a+0x44))
        o.call('new_at', a, NONE)
        o.call('new_at', a, 0x80000000)
        o.call('handle', a, NONE)
    assert set(o.counts) == set(ABI)
    assert all(entry in o.visited for entry, *_ in ABI.values())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--library', type=Path, default=ROOT/'build/libhalo2_engine.so')
    ap.add_argument('--report', type=Path, default=ROOT/'analysis/data-array-tests.json')
    args = ap.parse_args()
    oracle = Oracle(args.library.resolve())
    suite(oracle)
    report = dict(passed=True, xbe_sha256=EXPECTED, unicorn_version=U.__version__,
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                  source_sha256=hashlib.sha256((ROOT/'src/data_array.c').read_bytes()).hexdigest(),
                  abi_sha256=hashlib.sha256((ROOT/'config/data_array_abi.json').read_bytes()).hexdigest(),
                  test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  comparisons=dict(oracle.counts), total_comparisons=sum(oracle.counts.values()),
                  oracle='original XBE instructions, no function replacements',
                  scope='16 data-array routines; valid bounded allocations; not whole-game correctness')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__': main()
