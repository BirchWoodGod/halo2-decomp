#!/usr/bin/env python3
"""Lifecycle orchestration equivalence, with explicit controlled subsystem boundaries."""
import argparse,ctypes as C,hashlib,json,random,struct
from unicorn import x86_const as X
import unicorn as U
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED
from arena_oracle import Platform
FP=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32)
Dispatch=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32)
class Operations(C.Structure):
    _fields_=[('context',C.c_void_p),('control_fp',FP),('dispatch',Dispatch),('validate_variant',Dispatch)]
def suite(h):
    lib=h.lib;state=h.scratch+0x2000;other=state+0x2000;options=state+0x4000;seed=state+0x6000
    rng=random.Random(78);original=[];native=[];flip=False
    targets=set();table=bytes(h.read(0x440dd8,68*36))
    def events(read,write,out,kind,args):
        s=struct.unpack('<I',read(0x4e6948,4))[0]
        out.append((kind,args,s,bytes(read(s,8)),bytes(read(s+0x1120,0x18))))
        if flip and (kind=='validate' or (kind=='dispatch' and len(out)%7==0)):
            write(0x4e6948,struct.pack('<I',other if s==state else state))
        if kind=='dispatch':
            v=struct.unpack('<I',read(seed+4,4))[0]
            write(seed+4,struct.pack('<I',(v*33+args[0])&0xffffffff))
    def native_write(address,data):C.memmove(h.pointer+address-0x10000,data,len(data))
    ops=Operations(None,FP(lambda ctx,v,m:events(h.read,native_write,native,'fp',(v,m))),
        Dispatch(lambda ctx,f:events(h.read,native_write,native,'dispatch',(f,))),
        Dispatch(lambda ctx,v:events(h.read,native_write,native,'validate',(v,))))
    def hook(u,address,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if address==0x3212d6:kind='fp';args=struct.unpack('<II',u.mem_read(esp+4,8))
        elif address==0x19d650:kind='validate';args=(u.reg_read(X.UC_X86_REG_EBX),)
        elif address in targets:kind='dispatch';args=(address,)
        else:return
        # The initial direct arena call in game_initialize is recovered, not a subsystem event.
        if address==0x123b30 and struct.unpack('<I',u.mem_read(esp,4))[0]==0x137c28:return
        events(u.mem_read,u.mem_write,original,kind,args)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    h.u.hook_add(U.UC_HOOK_CODE,hook)
    lib.h2_game_initialize.argtypes=[C.POINTER(Memory),C.POINTER(Platform),C.POINTER(Operations)]
    lib.h2_game_initialize.restype=None
    for name in ['set_options','initialize_for_map','dispose_from_map','initialize_for_structure','dispose_from_structure']:
        f=getattr(lib,'h2_game_'+name);f.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+([C.c_uint32] if name in ['set_options','initialize_for_map'] else []);f.restype=None
    platform=Platform() # Initialized arena path must not call any platform callback.
    functions=[('initialize',0x137c20,None),('set_options',0x137dd0,None),('initialize_for_map',0x137ca0,2),('dispose_from_map',0x137d00,3),('initialize_for_structure',0x137d40,4),('dispose_from_structure',0x137da0,5)]
    for real_table in [False,True]:
        for iteration in range(12):
            flip=bool(iteration%2)
            for name,address,column in functions:
                h.write(state,rng.randbytes(0x1200));h.write(other,rng.randbytes(0x1200))
                h.write(options,rng.randbytes(0x1118));h.write(options,struct.pack('<I',iteration%3))
                h.write(options+0x178,struct.pack('<I',0 if iteration%4<2 else 1))
                h.write(0x4e6948,struct.pack('<I',state));h.write(0x4e7408,struct.pack('<I',seed));h.write(seed,bytes(8))
                h.write(0x4e3b60,b'\1');h.write(0x4e6080,struct.pack('<IIII',state,0,0,0xffffffff))
                h.write(0x4686c4,struct.pack('<H',iteration));h.write(0x55e755,b'\0')
                entries=bytearray(table)
                if not real_table:
                    for i in range(68):
                        for c in range(6):
                            value=0x3000200+(i*6+c)*4
                            if c and (i+iteration)%3==0:value=0
                            struct.pack_into('<I',entries,i*36+c*4,value)
                h.write(0x440dd8,bytes(entries))
                targets.clear()
                selected_column=0 if name=='initialize' else column
                if selected_column is not None:
                    targets.update(struct.unpack_from('<I',entries,i*36+selected_column*4)[0] for i in range(68));targets.discard(0)
                original.clear();native.clear()
                args=[options] if name in ['set_options','initialize_for_map'] else []
                if name=='initialize':call=lambda:lib.h2_game_initialize(h.memory,C.byref(platform),C.byref(ops))
                else:call=lambda:getattr(lib,'h2_game_'+name)(h.memory,C.byref(ops),*args)
                h.call(name,address,{},args,call)
                assert original==native,(name,real_table,iteration,original,native)
                if selected_column is not None:
                    order=range(67,-1,-1) if selected_column in [3,5] else range(68)
                    expected=[struct.unpack_from('<I',entries,i*36+selected_column*4)[0] for i in order]
                    expected=[x for x in expected if x or selected_column==0]
                    assert [e[1][0] for e in native if e[0]=='dispatch']==expected
    h.write(0x440dd8,table)
def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/game-lifecycle-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ['src/game_lifecycle.c','tests/game_lifecycle_oracle.py','tests/hash_crc_oracle.py']},scope='Six orchestration routines, real and synthetic lifecycle tables. Subsystem bodies, FP control, and variant validation are controlled boundaries. Not full startup or gameplay.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
