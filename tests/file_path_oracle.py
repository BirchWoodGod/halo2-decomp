#!/usr/bin/env python3
"""Original path helpers and CRT strncpy execute unchanged."""
import argparse
import ctypes as C
import hashlib
import itertools
import json
import random
from hash_crc_oracle import Harness
from data_array_oracle import ROOT, Memory, EXPECTED


def suite(h):
    lib = h.lib
    rng = random.Random(0x137320)
    for name, argc in [('append',2),('parent',1),('resolve',2)]:
        fn = getattr(lib,'h2_file_path_'+name)
        fn.argtypes = [C.POINTER(Memory)]+[C.c_uint32]*argc
        fn.restype = None
    source = h.table+0x1000
    bases = [b'',b'a',b'd:',b'd:\\',b'd:\\maps',b'X'*254,b'X'*255,b'X'*254+b'\\']
    components = [b'',b'a',b'\\maps',b'x'*255,b'x'*256,b'x'*300]
    for base, component, alignment in itertools.product(bases,components,range(4)):
        destination = h.table+alignment
        h.write(h.table,rng.randbytes(0x210))
        h.write(destination,base+b'\0')
        h.write(source,component+b'\0')
        before = h.read(destination,257)
        h.call('append',0x137320,dict(esi=destination,edi=source),[],
               lambda:lib.h2_file_path_append(h.memory,destination,source))
        if not component:
            assert h.read(destination,257)==before
        else:
            joined=base+(b'\\' if base and not base.endswith(b'\\') else b'')+component
            assert h.read(destination,len(joined[:255])+1)==joined[:255]+b'\0'
            if len(base)==255 and not base.endswith(b'\\'):
                assert h.read(destination+256,1)==b'\0'
    paths = [b'',b'a',b'file.bin',b'd:\\',b'd:\\maps\\file.map',b'd:maps',
             b'/maps/file',b'\\maps\\file',b'C:\\maps',b'z:\\file',
             b'1:\\file',b'X'*255,b'X'*256,b'X'*300]
    paths.extend(bytes([first])+b':\\file' for first in range(1,256))
    prefix=h.read(0x453588,3)
    assert prefix==b'd:\\'
    for i,path in enumerate(paths):
        destination=h.table+i%4
        h.write(h.table,rng.randbytes(0x210))
        h.write(source,path+b'\0')
        h.call('resolve',0x1374c0,dict(esi=destination,edi=source),[],
               lambda:lib.h2_file_path_resolve(h.memory,destination,source))
        absolute=len(path)>=3 and (65<=path[0]<=90 or 97<=path[0]<=122) and path[1:3]==b':\\'
        expected=(path if absolute else prefix+path)[:255]+b'\0'
        assert h.read(destination,len(expected))==expected
    for path,alignment in itertools.product(paths[:14]+[b'\\',b'a\\b\\',b'a/b'],range(4)):
        address=h.table+alignment
        h.write(h.table,rng.randbytes(0x210));h.write(address,path+b'\0')
        h.call('parent',0x1373c0,dict(ecx=address),[],
               lambda:lib.h2_file_path_parent(h.memory,address))
        expected=path.rsplit(b'\\',1)[0] if b'\\' in path else b''
        assert h.read(address,len(expected)+1)==expected+b'\0'
    # The original truncates length to signed 16 bits. Verify that behavior,
    # including writes before the path for negative lengths, in mapped storage.
    address=h.table+0x10000
    for n in [32767,32768,32769,65535,65536]:
        h.write(address-0x8000,b'\xa5'*0x8000)
        h.write(address,b'x'*n+b'\0')
        h.call('parent_signed_length',0x1373c0,dict(ecx=address),[],
               lambda:lib.h2_file_path_parent(h.memory,address))


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/file-path-tests.json')
    args=p.parse_args();library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/file_path.c','tests/file_path_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,
                library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                comparisons=h.counts,total_comparisons=sum(h.counts.values()),
                source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                scope='Three path helpers with original CRT calls intact. Full memory comparison, drive syntax, truncation, padding, signed length boundaries. Append/resolve use disjoint buffers and append bases at most 255 bytes. No host filesystem translation or file I/O.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
