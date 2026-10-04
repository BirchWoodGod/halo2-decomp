#!/usr/bin/env python3
"""Contrast original-instruction emulation with the same arithmetic on host x87."""
import ctypes as C,hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,EXPECTED

def main():
    source=ROOT/'tests/native_x87_power_probe.c';library=ROOT/'build/libhandoff_x87_probe.so'
    subprocess.run(['cc','-O2','-shared','-fPIC',str(source),'-o',str(library)],check=True)
    native=C.CDLL(str(library)).probe_power;native.argtypes=[C.c_double,C.c_double];native.restype=C.c_double
    h=Harness(ROOT/'build/libhalo2_engine.so')
    try:
        sequence=bytes(h.u.mem_read(0x327f84,20))
        assert sequence==bytes.fromhex('d9c0d9fcdce1d9c9d9e0d9f0d9e8dec1d9fdddd9')
        assert sequence in library.read_bytes(),'native arithmetic opcode sequence differs'
    finally:h.close()
    H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    original=ROOT/'analysis/handoff-math-probe.json';data=json.loads(original.read_text())
    assert data['source_sha256']==H(ROOT/'scripts/probe-handoff-math.py')
    rows=[]
    for sample in data['samples']:
        if sample['base']<=0:continue # This native diagnostic implements only the normal path.
        result=native(sample['base'],sample['exponent'])
        rows.append(dict(base=sample['base'],exponent=sample['exponent'],unicorn=sample['original'],native_x87=result,exact_match=result==sample['original']))
    report=dict(probe_completed=True,xbe_sha256=EXPECTED,original_probe_sha256=H(original),source_sha256=H(source),script_sha256=H(Path(__file__)),library_sha256=H(library),arithmetic_opcodes=sequence.hex(),samples=rows,scope='Host x87 normal arithmetic path versus Unicorn executing original CRT. Matching arithmetic opcodes verified. Not Xbox hardware evidence or full CRT recovery. Emulator differences invalidate treating its transcendental last-bit outputs as authoritative hardware results.')
    (ROOT/'analysis/native-handoff-math-probe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
