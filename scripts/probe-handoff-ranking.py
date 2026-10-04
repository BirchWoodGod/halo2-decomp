#!/usr/bin/env python3
"""Compare original ranking decisions with a host-power hypothesis; no recovery claim."""
import hashlib,json,math,random,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,EXPECTED
from engine_pools_oracle import STACK,STOP
P=lambda n:struct.pack('<I',n&0xffffffff)
F=lambda n:struct.pack('<f',n)
def f32(n):return struct.unpack('<f',F(n))[0]
def sv(n):return (n&0xffffffff)-(0x100000000 if n&0x80000000 else 0)
def main():
    library=ROOT/'build/libhalo2_engine.so';h=Harness(library);session=h.table;stub=STOP+0x600;rng=random.Random(0x619b0)
    capture=[];mismatches=[];score_mismatches=0;cases=0;branches={'integer':0,'positive_power':0,'negative_power':0}
    def hook(u,addr,size,ctx):
        if addr==0x61a95:
            sp=u.reg_read(X.UC_X86_REG_ESP);capture.append(struct.unpack('<f',u.mem_read(sp+0x14,4))[0])
        else:branches['positive_power' if addr==0x61a71 else 'negative_power']+=1
    for addr in [0x61a95,0x61a71,0x61a88]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=addr,end=addr)
    try:
        # FNINIT then jump into the unmodified ranking function and CRT callees.
        code=b'\xdb\xe3\xe9'+struct.pack('<i',0x619b0-(stub+7));h.u.mem_write(stub,code)
        for sample in range(256):
            candidate=session+0x10c;incumbent=session
            ca,ia=[rng.randrange(-10000,10001) for _ in range(2)]
            cr,ir=[rng.randrange(-1000,1001) for _ in range(2)];cap=rng.randrange(1,1000)
            scale=f32([0.0001,0.01,1.0][sample%3]);latency_scale=f32([0.0001,0.01,1.0][sample//3%3]);exponent=f32([0.,0.5,1.,1.5,2.][sample%5])
            left=f32(f32(sv(min(cr,cap)-min(ir,cap)))*scale)
            delta=f32(f32(sv(ia-ca))*latency_scale)
            host_power=math.pow(abs(delta),exponent)
            hypothesis=f32(left+host_power if delta>0 else left-host_power)
            bits=struct.unpack('<I',F(hypothesis))[0]
            thresholds=[hypothesis,struct.unpack('<f',P(bits-1))[0],struct.unpack('<f',P(bits+1))[0]]
            for threshold in thresholds:
                if not math.isfinite(threshold):continue
                h.write(session,bytes(0x300))
                for p,a,r in [(candidate,ca,cr),(incumbent,ia,ir)]:
                    h.write(p+0x9c,P(7));h.write(p+0xf8,P(10));h.write(p+0xa4,P(a));h.write(p+0x94,P(r))
                for p,v in [(0x4ce074,scale),(0x4ce078,latency_scale),(0x4ce07c,exponent),(0x45dbd8,0.),(0x44ae90,threshold)]:h.write(p,F(v))
                h.write(0x4ce0c4+12,P(cap))
                sp=STACK+0x8000;h.u.mem_write(sp,P(STOP)+P(3));h.u.reg_write(X.UC_X86_REG_ESP,sp)
                for reg,val in [(X.UC_X86_REG_ECX,session),(X.UC_X86_REG_EDX,1),(X.UC_X86_REG_EAX,0),(X.UC_X86_REG_EFLAGS,2),(X.UC_X86_REG_MXCSR,0x1f80)]:h.u.reg_write(reg,val)
                capture.clear()
                try:h.u.emu_start(stub,STOP,count=200000)
                except Exception:
                    print('failed',sample,hex(h.u.reg_read(X.UC_X86_REG_EIP)),ca,ia,cr,ir,exponent);raise
                assert h.u.reg_read(X.UC_X86_REG_EIP)==STOP and h.u.reg_read(X.UC_X86_REG_ESP)==sp+8
                assert len(capture)==1
                result=h.u.reg_read(X.UC_X86_REG_EAX)&255;expected=int(hypothesis>threshold)
                assert result==int(capture[0]>threshold)
                score_mismatches+=F(capture[0])!=F(hypothesis);cases+=1
                if result!=expected:mismatches.append(dict(sample=sample,candidate_latency=ca,incumbent_latency=ia,candidate_rate=cr,incumbent_rate=ir,cap=cap,scale=scale,latency_scale=latency_scale,exponent=exponent,threshold=threshold,original_score=capture[0],host_score=hypothesis,original_result=result,host_result=expected))
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    report=dict(probe_completed=True,xbe_sha256=EXPECTED,library_sha256=H(library),source_sha256=H(Path(__file__)),cases=cases,branches=branches,score_mismatches=score_mismatches,decision_mismatches=mismatches,scope='Original ranking and all CRT callees with clean x87/default MXCSR, finite tie-break inputs, thresholds at and adjacent to host float score. Host power hypothesis is investigative, not a native implementation or exhaustive equivalence proof.')
    (ROOT/'analysis/handoff-ranking-probe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='decision_mismatches'},indent=2));print('Decision mismatches:',len(mismatches))
if __name__=='__main__':main()
