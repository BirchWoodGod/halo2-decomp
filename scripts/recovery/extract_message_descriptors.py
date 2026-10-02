#!/usr/bin/env python3
"""Extract constant message descriptors with original-write traces for review.
This is build-time recovery evidence, not a runtime x86 translation layer.
"""
import sys,struct,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tests'))
from hash_crc_oracle import Harness
from unicorn import x86_const as X
import unicorn as U
from iced_x86 import Decoder,Formatter,FormatterSyntax
from data_array_oracle import EXPECTED
functions=[('discovery',0xac800),('connection',0xacb10),('session',0xadab0),('membership',0xaf680),('parameters',0xb2220),('simulation',0xb2680),('synchronous',0xb2b30),('results',0xb2cc0),('test',0xb2de0)]
def main():
 h=Harness(ROOT/'build/libhalo2_engine.so');result=[];formatter=Formatter(FormatterSyntax.NASM)
 try:
  for name,address in functions:
   instructions=[]
   for ins in Decoder(32,h.read(address,4096),ip=address):
    line=formatter.format(ins);instructions.append(f'{ins.ip:08x} {line}')
    assert line.split()[0] in ['mov','xor','push','pop','ret'],line
    if line=='ret':break
   else:raise AssertionError('missing return')
   table=h.table;h.u.mem_write(table,b'\xa5'*0x600);writes=[]
   def trace(u,access,at,size,value,ctx):
    if table<=at<table+0x600:writes.append(dict(offset=at-table,size=size,value=value))
   handle=h.u.hook_add(U.UC_HOOK_MEM_WRITE,trace)
   stack=0x2008000;stop=0x3000000
   h.u.mem_write(stack,struct.pack('<I',stop));h.u.reg_write(X.UC_X86_REG_ESP,stack);h.u.reg_write(X.UC_X86_REG_EAX,table)
   h.u.emu_start(address,stop,count=1000);h.u.hook_del(handle)
   assert h.u.reg_read(X.UC_X86_REG_EIP)==stop
   descriptors=[]
   for index in sorted({w['offset']//32 for w in writes}):
    at=table+index*32;raw=bytes(h.u.mem_read(at,32))
    assert raw[:4]==b'\1\xa5\xa5\xa5'
    words=struct.unpack('<7I',raw[4:]);label=h.read(words[0],100).split(b'\0')[0].decode('ascii')
    expected={(index*32,1)}|{(index*32+i,4) for i in range(4,32,4)}
    assert {(w['offset'],w['size']) for w in writes if w['offset']//32==index}==expected
    descriptors.append(dict(index=index,name=label,words=list(words)))
   result.append(dict(group=name,address=f'{address:08x}',descriptors=descriptors,writes=writes,instructions=instructions))
 finally:h.close()
 (ROOT/'config/message_descriptors.json').write_text(json.dumps(dict(xbe_sha256=EXPECTED,functions=result),indent=2)+'\n')
 print('Extracted',sum(len(f['descriptors']) for f in result),'descriptors in',len(result),'routines')
if __name__=='__main__':main()
