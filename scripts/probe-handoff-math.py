#!/usr/bin/env python3
"""Probe original CRT power boundary; this is not a recovered implementation."""
import hashlib,json,math,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,EXPECTED
from engine_pools_oracle import STACK,STOP
from unicorn import x86_const as X

def main():
    library=ROOT/'build/libhalo2_engine.so';h=Harness(library);stub=STOP+0x600;data=h.table;rows=[]
    try:
        for base,exponent in [(2.,3.),(9.,.5),(4.,0.),(0.,2.),(.25,.5),(1.,1.5),(16.,.25),(2.,-2.)]:
            # Original ABI: ST1 base, ST0 exponent. Run all CRT instructions.
            h.u.mem_write(data,struct.pack('<ff',base,exponent))
            code=(b'\xdb\xe3'+ # FNINIT: clean x87 state for each sample
                  b'\xd9\x05'+struct.pack('<I',data)+
                  b'\xd9\x05'+struct.pack('<I',data+4))
            call=stub+len(code)
            code+=b'\xe8'+struct.pack('<i',0x372d48-(call+5))
            code+=b'\xdd\x1d'+struct.pack('<I',data+16)+b'\x90'
            h.u.mem_write(stub,code);h.u.reg_write(X.UC_X86_REG_ESP,STACK+0x8000)
            h.u.emu_start(stub,stub+len(code),count=100000)
            assert h.u.reg_read(X.UC_X86_REG_EIP)==stub+len(code)
            assert h.u.reg_read(X.UC_X86_REG_ESP)==STACK+0x8000
            bits=bytes(h.u.mem_read(data+16,8));value=struct.unpack('<d',bits)[0];reference=math.pow(base,exponent)
            assert math.isclose(value,reference,rel_tol=1e-12,abs_tol=1e-15)
            rows.append(dict(base=base,exponent=exponent,original=value,original_double_le=bits.hex(),host_reference=reference,exact_host_match=value==reference))
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=H(library),source_sha256=H(Path(__file__)),samples=rows,scope='Original CRT00372d48 with ST1 base/ST0 exponent; no callee replacements. Finite representative inputs and clean x87 state, result stored as double. Establishes power semantics only; not exhaustive CRT correctness, ranking fidelity, or native implementation validation.')
    (ROOT/'analysis/handoff-math-probe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
