#!/usr/bin/env python3
"""Native Linux filesystem integration; no SDK mocks or original execution."""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib
from hash_crc_oracle import Harness
from file_open_oracle import OpenPlatform
from data_array_oracle import ROOT, Memory, EXPECTED


def suite(h, executable):
    lib=h.lib;checks=[]
    lib.h2_host_files_create.argtypes=[C.POINTER(Memory)];lib.h2_host_files_create.restype=C.c_void_p
    lib.h2_host_files_mount.argtypes=[C.c_void_p,C.c_char,C.c_char_p];lib.h2_host_files_mount.restype=C.c_int
    lib.h2_host_files_operations.argtypes=[C.c_void_p];lib.h2_host_files_operations.restype=OpenPlatform
    lib.h2_host_files_open_count.argtypes=[C.c_void_p];lib.h2_host_files_open_count.restype=C.c_uint32
    lib.h2_host_files_destroy.argtypes=[C.c_void_p];lib.h2_host_files_destroy.restype=None
    common=[C.POINTER(Memory),C.POINTER(OpenPlatform)]
    for name,n in [('open',3),('exists',1),('size',2),('close',1),('write',3),('set_end',2)]:
        fn=getattr(lib,'h2_file_'+name);fn.argtypes=common+[C.c_uint32]*n;fn.restype=C.c_uint8
    lib.h2_file_read.argtypes=common+[C.c_uint32]*3+[C.c_uint8];lib.h2_file_read.restype=C.c_uint8
    lib.h2_file_seek.argtypes=common+[C.c_uint32]*2+[C.c_uint8];lib.h2_file_seek.restype=C.c_uint8
    lib.h2_network_config_load.argtypes=common+[C.c_uint32];lib.h2_network_config_load.restype=C.c_uint8
    descriptors_before=len(os.listdir('/proc/self/fd'))
    host=lib.h2_host_files_create(h.memory);assert host
    ops=lib.h2_host_files_operations(host)
    file=h.table;second=file+0x200;buffer=file+0x500;error=file+0x800;workspace=file+0x1000
    def reference(address,path):h.write(address,bytes(0x110));h.write(address+8,path.encode()+b'\0')
    def call(name,*args):return getattr(lib,'h2_file_'+name)(h.memory,C.byref(ops),*args)
    try:
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'Maps').mkdir();(root/'Maps'/'Test.bin').write_bytes(b'abcdef')
            assert lib.h2_host_files_mount(host,b'd',str(root).encode())
            assert lib.h2_host_files_mount(host,b'z',str(root).encode())
            reference(file,'maps\\test.BIN')
            assert call('exists',file) and call('size',file,error) and h.u32(error)==6
            assert call('open',file,1,error)
            assert call('read',file,buffer,3,0) and h.read(buffer,3)==b'abc'
            assert h.u32(file+0x10c)==3
            assert not call('read',file,buffer,5,1) and h.read(buffer,3)==b'def'
            assert h.u32(file+0x10c)==6 and ops.last_error(host)==0x26
            assert call('seek',file,1,0) and call('read',file,buffer,2,0)
            assert h.read(buffer,2)==b'bc'
            assert call('close',file) and lib.h2_host_files_open_count(host)==0
            checks.append('case-insensitive paths, size, exact/short reads, seek and close')

            reference(file,'d:\\Maps\\Test.bin');reference(second,'D:\\maps\\test.bin')
            assert call('open',file,1,error) and call('open',second,1,error)
            assert call('close',second)
            assert not call('open',second,2,error) and h.u32(error)==5
            assert call('close',file)
            assert call('open',file,3,error)
            h.write(buffer,b'XYZ');assert call('write',file,buffer,3)
            assert call('set_end',file,4) and call('close',file)
            assert (root/'Maps'/'Test.bin').read_bytes()==b'XYZd'
            assert call('open',file,7,error) and h.u32(file+0x10c)==4
            h.write(buffer,b'!');assert call('write',file,buffer,1) and call('close',file)
            assert (root/'Maps'/'Test.bin').read_bytes()==b'XYZd!'
            checks.append('shared readers, conflicting writer, writes, truncate and seek-to-end')

            reference(file,'missing.bin')
            assert not call('exists',file) and not call('open',file,1,error) and h.u32(error)==1
            reference(file,'q:\\missing.bin')
            assert not call('open',file,1,error) and h.u32(error)==4
            for path in ['d:\\..\\outside','d:\\Maps\\..\\..\\outside']:
                reference(file,path);assert not call('exists',file)
            reference(file,'d:\\Maps\\..\\Maps\\Test.bin');assert call('exists',file)
            (root/'alias').symlink_to(root/'Maps'/'Test.bin')
            reference(file,'alias');assert not call('exists',file) and not call('open',file,1,error)
            reference(file,'Maps');assert call('exists',file) and not call('open',file,1,error)
            (root/'case').write_bytes(b'a');(root/'CASE').write_bytes(b'b')
            reference(file,'CaSe');assert not call('exists',file)
            reference(file,'case');assert call('exists',file)
            checks.append('missing/unmounted paths, mount bounds, parent components, symlinks and ambiguous case')

            (root/'remove.bin').write_bytes(b'delete on close')
            reference(file,'remove.bin');assert call('open',file,0x41,error)
            assert (root/'remove.bin').exists()
            assert call('close',file) and not (root/'remove.bin').exists()
            # Closing a renamed/replaced delete-on-close path must not delete
            # a different file that now occupies its name.
            (root/'replace.bin').write_bytes(b'old');reference(file,'replace.bin')
            assert call('open',file,0x41,error)
            (root/'replace.bin').rename(root/'old.bin');(root/'replace.bin').write_bytes(b'new')
            assert not call('close',file) and (root/'replace.bin').read_bytes()==b'new'
            assert lib.h2_host_files_open_count(host)==0
            checks.append('delete-on-close and replacement-file protection')

            # Sparse metadata verifies the high word without writing GiB of data.
            with (root/'large.bin').open('wb') as stream:stream.truncate((1<<32)+9)
            path=(C.c_uint8*256)();path[:len(b'd:\\large.bin')]=b'd:\\large.bin'
            info=(C.c_uint8*36)();assert ops.metadata(host,path,0,info)
            assert struct.unpack('<II',bytes(info)[28:36])==(1,9)
            reference(file,'large.bin');assert call('size',file,error) and h.u32(error)==9
            done=C.c_uint32(99)
            assert not ops.read(host,0xffffffff,buffer,1,C.byref(done)) and done.value==0
            assert ops.last_error(host)==6
            checks.append('64-bit metadata and invalid-handle count/error behavior')
            reference(file,'Maps\\Test.bin')
            assert call('open',file,0,error)
            assert not call('read',file,buffer,1,1)
            assert not call('write',file,buffer,1)
            assert call('close',file)
            handles=[]
            for _ in range(256):
                assert call('open',file,1,error)
                handles.append(h.u32(file+0x108))
            assert len(set(handles))==256 and lib.h2_host_files_open_count(host)==256
            assert not call('open',second,1,error)
            for handle in handles:assert ops.close(host,handle)
            assert lib.h2_host_files_open_count(host)==0
            checks.append('access rights, handle-table exhaustion and full release')

            config=root/'player_configuration_cache.dat'
            assert not lib.h2_network_config_load(h.memory,C.byref(ops),workspace)
            data=bytearray(0x8e4c);struct.pack_into('<7I',data,0,8,0,0,*([0xffffffff]*4))
            struct.pack_into('<I',data,4,zlib.crc32(data[8:])^0xffffffff)
            for kind in ['valid','wrong_size','bad_crc','bad_version']:
                payload=bytearray(data)
                if kind=='wrong_size':payload.pop()
                if kind=='bad_crc':payload[4]^=1
                if kind=='bad_version':struct.pack_into('<I',payload,0,7)
                config.write_bytes(payload)
                result=lib.h2_network_config_load(h.memory,C.byref(ops),workspace)
                assert result==int(kind=='valid'),kind
                assert lib.h2_host_files_open_count(host)==0
                if kind=='valid':assert h.read(0x4cf970,len(data))==data
            checks.append('real-file configuration load, missing/wrong size/bad CRC/invalid version and handle cleanup')
            config.write_bytes(data)
            completed=subprocess.run([str(executable),'--probe-config',str(ROOT/'default.xbe'),str(root)],capture_output=True,text=True)
            assert completed.returncode==0,completed.stderr
            assert 'Configuration loaded through native Linux I/O: version=8 records=0' in completed.stdout
            config.write_bytes(b'invalid')
            completed=subprocess.run([str(executable),'--probe-config',str(ROOT/'default.xbe'),str(root)],capture_output=True,text=True)
            assert completed.returncode==1 and 'rejected' in completed.stderr
            checks.append('standalone Linux configuration probe accepts valid file and rejects invalid file')
            # Deliberately leave one handle open: destructor owns cleanup.
            reference(file,'Maps\\Test.bin');assert call('open',file,1,error)
    finally:
        lib.h2_host_files_destroy(host)
    assert len(os.listdir('/proc/self/fd'))==descriptors_before
    checks.append('backend destruction releases outstanding handles and mount descriptors')
    return checks


def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so')
    p.add_argument('--report',default='analysis/host-file-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    executable=library.parent/'halo2-engine-host'
    try:checks=suite(h,executable)
    finally:h.close()
    sources=['src/host/files.c','include/halo2/host_files.h','src/file_io.c','src/file_path.c',
             'src/network_config.c','src/crc.c','src/host/main.c','tests/host_files_test.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                host_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                checks=checks,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},
                scope='Real Linux filesystem and recovered engine integration, temporary fixtures only. No SDK mocks or original instruction execution. Configuration load demonstrated; not game startup. Metadata timestamps and cross-process sharing equivalence unimplemented.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
