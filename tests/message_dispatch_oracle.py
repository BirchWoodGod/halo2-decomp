#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations,Ticks,Provider
Encode=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class Platform(C.Structure):
    _fields_=[('context',C.c_void_p),('encode',Encode)]
class NativeCodec(C.Structure):
    _fields_=[('memory',C.POINTER(Memory)),('clock',C.POINTER(Operations)),('scratch',C.c_uint32)]

def suite(h):
    stream=h.table;buffer=stream+0x200;payload=stream+0x2400;scratch=stream+0x4000
    original=[];native=[];frame={};ticks_value=0
    callback=Ticks(lambda ctx:(native.append('ticks'),ticks_value)[1]);clock=Operations(None,callback,Provider())
    context=NativeCodec(h.memory,C.pointer(clock),scratch);platform=Platform()
    init=h.lib.h2_message_native_codec_init;init.argtypes=[C.POINTER(Platform),C.POINTER(NativeCodec)];init.restype=None;init(C.byref(platform),C.byref(context))
    encode=h.lib.h2_message_native_encode;encode.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*5;encode.restype=C.c_uint8
    decode=h.lib.h2_message_native_decode;decode.argtypes=encode.argtypes;decode.restype=C.c_int32
    supported=h.lib.h2_message_native_can_encode;supported.argtypes=[C.c_uint32];supported.restype=C.c_uint8
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if address in [0x7ba10,0x7c110]:
            n=64 if address==0x7ba10 else 76;offset=0x140 if n==64 else 0x4c
            frame.update(address=esp-offset,size=n);u.mem_write(esp-offset,bytes(n));return
        original.append('ticks');u.reg_write(X.UC_X86_REG_EAX,ticks_value)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    for address in [0x7ba10,0x7c110,0x3314b0]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    descriptors=[d for g in json.loads((ROOT/'config/message_descriptors.json').read_text())['functions'] for d in g['descriptors']]
    for d in descriptors:
        if d['index']>=25:continue
        index=d['index'];writer,reader=d['words'][4:6];size=d['words'][2]
        assert supported(writer)==1
        for iteration in range(32):
            original.clear();native.clear();frame.clear();ticks_value=(0xfffffff0+iteration)&0xffffffff
            h.write(stream,bytes(0x100));h.write(buffer,bytes(0x1800));h.write(payload,bytes(0x1000));h.write(scratch,bytes(76));h.write(0x510550,bytes(4))
            # Safe, nontrivial fixtures for each descriptor family. Writers'
            # output is checked against original x86 before feeding readers.
            h.write(payload,struct.pack('<II',iteration,0x11223344))
            if index==3:
                h.write(payload+12,bytes(0x714));h.write(payload+12+8,struct.pack('<II',0xffffffff,0xffffffff))
                h.write(payload+12+0xa8,struct.pack('<I',0xffffffff))
            elif index==8:h.write(payload+12,struct.pack('<I',iteration%2))
            elif index==22:h.write(payload+0x5c,struct.pack('<I',iteration%3))
            elif index==24:h.write(payload+24,struct.pack('<H',iteration%2))
            else:h.write(payload+8,struct.pack('<I',iteration%16))
            position=iteration%32;capacity=[0x1800,0,8,16][iteration%4]
            h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<I',position))
            def finish_scratch():
                if frame:
                    n=frame['size'];assert h.read(scratch,n)==bytes(h.u.mem_read(frame['address'],n))
                    C.memmove(h.pointer+scratch-BASE,bytes(76),76)
            def run_write():
                if iteration%2:platform.encode(platform.context,writer,stream,size,payload)
                else:assert encode(h.memory,C.byref(clock),writer,stream,size,payload,scratch)==1
                finish_scratch()
            h.call('encode_'+d['name'],writer,{},[stream,size,payload],run_write)
            assert native==original,(d['name'],iteration,'encode events')
            original.clear();native.clear();frame.clear()
            h.write(payload,bytes([0x55])*0x1000);h.write(stream+16,struct.pack('<IB',position,1 if iteration%7==0 else 0));h.write(scratch,bytes(76))
            def run_read():
                answer=decode(h.memory,C.byref(clock),reader,stream,size,payload,scratch)
                assert answer in [0,1];finish_scratch();return answer
            h.call('decode_'+d['name'],reader,{},[stream,size,payload],run_read,255)
            assert native==original,(d['name'],iteration,'decode events')
    # Unknown and unrecovered callbacks must not call clocks or touch guest data.
    before=h.read(BASE,h.size);native.clear()
    unsupported_count=0
    for writer,reader in [(d['words'][4],d['words'][5]) for d in descriptors if d['index']>=25]+[(0,0),(0xffffffff,0xffffffff),(0xad230+1,0xad290+1)]:
        assert supported(writer)==0
        assert encode(h.memory,C.byref(clock),writer,0,0,0,0)==0
        assert decode(h.memory,C.byref(clock),reader,0,0,0,0)==-1
        unsupported_count+=1
    assert before==h.read(BASE,h.size) and not native
    return unsupported_count

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/message-dispatch-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:unsupported=suite(h)
    finally:h.close()
    sources=['src/message_dispatch.c','include/halo2/message_dispatch.h','src/network_messages.c','include/halo2/network_messages.h','src/session_description.c','include/halo2/session_description.h','src/bitstream.c','src/text_codec.c','src/network_config.c','config/message_descriptors.json','tests/message_dispatch_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),unsupported_pairs=unsupported,source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Native callback dispatch for descriptors 0-24 compared to original registered encoder/decoder addresses; half the encoding calls use the C queue adapter. Full memory/decoder AL and clock events; SDK ticks controlled; description locals seeded at entry and compared. All engine callees intact. Unsupported callbacks leave memory unchanged. Native integration, not additional recovered Xbox routines. No live networking.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
