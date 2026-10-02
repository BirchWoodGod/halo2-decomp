#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STACK,STOP
from data_array_oracle import ROOT,Memory,EXPECTED
from network_state_oracle import Operations
Decode=C.CFUNCTYPE(C.c_uint8,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
Deliver=C.CFUNCTYPE(None,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32)
class ReaderOps(C.Structure):
    _fields_=[('context',C.c_void_p),('decode',Decode),('deliver',Deliver)]

def suite(h):
    rng=random.Random(0x7afd0);owner=h.table;stream=owner+0x200;table=owner+0x1000;wire=owner+0x3000;scratch=owner+0x8000;stub=STOP+0x800
    h.u.mem_map(STACK-0x10000,0x10000)
    original=[];native=[];frames={};last_size={'o':0,'n':0};iteration=0;result=1;incoming=bytes(0x10008)
    template=bytearray(45*32)
    for group in json.loads((ROOT/'config/message_descriptors.json').read_text())['functions']:
        for d in group['descriptors']:struct.pack_into('<8I',template,d['index']*32,1,*d['words'])
    native_decode=h.lib.h2_message_native_decode;native_decode.argtypes=[C.POINTER(Memory),C.POINTER(Operations)]+[C.c_uint32]*5;native_decode.restype=C.c_int32
    def nw(p,data):C.memmove(h.pointer+p-BASE,data,len(data))
    def event(read,write,events,which,kind,args,payload,size):
        events.append((kind,args,bytes(read(payload,size)),bytes(read(stream,0x34))))
        if kind=='decode':last_size[which]=size
        else:
            if iteration%5==0:write(owner+16,bytes(4))
            if iteration%7==0:write(table+10*32,b'\0')
    def decode(ctx,function,s,size,payload):
        event(h.read,nw,native,'n','decode',(function,s,size),payload,size)
        if function==stub:
            nw(s+16,struct.pack('<I',(h.u32(s+16)+8)&0xffffffff))
            if iteration%3==0:nw(owner+16,struct.pack('<I',0xabcdef00))
            return result
        answer=native_decode(h.memory,None,function,s,size,payload,owner+0x7000)
        assert answer in [0,1],hex(function)
        return answer
    def deliver(ctx,handler,kind,payload,address):event(h.read,nw,native,'n','deliver',(handler,kind,address),payload,last_size['n'])
    decode_cb=Decode(decode);deliver_cb=Deliver(deliver);ops=ReaderOps(None,decode_cb,deliver_cb)
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x7afe0:
            aligned=esp+0x10014;frames.update(header=aligned-0x1000c,payload=aligned-0x10000)
            u.mem_write(frames['header'],incoming[:8]);u.mem_write(frames['payload'],incoming[8:]);return
        if at==0x938e0:
            payload=u.reg_read(X.UC_X86_REG_ECX);args=(u.reg_read(X.UC_X86_REG_EDX),u.reg_read(X.UC_X86_REG_EAX),struct.unpack('<I',u.mem_read(esp+4,4))[0])
            event(u.mem_read,u.mem_write,original,'o','deliver',args,payload,last_size['o']);purge=4;answer=None
        else:
            s,n,payload=struct.unpack('<III',u.mem_read(esp+4,12));event(u.mem_read,u.mem_write,original,'o','decode',(at,s,n),payload,n)
            if at!=stub:return
            pos=struct.unpack('<I',u.mem_read(s+16,4))[0];u.mem_write(s+16,struct.pack('<I',(pos+8)&0xffffffff))
            if iteration%3==0:u.mem_write(owner+16,struct.pack('<I',0xabcdef00))
            purge=12;answer=result
        if answer is not None:u.reg_write(X.UC_X86_REG_EAX,answer)
        u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for address in [0x7afe0,0x938e0,0xac530,0xad290,0xad2e0,stub]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    process=h.lib.h2_message_reader_process;process.argtypes=[C.POINTER(Memory),C.POINTER(ReaderOps)]+[C.c_uint32]*4;process.restype=C.c_uint8
    for iteration in range(384):
        original.clear();native.clear();last_size.update(o=0,n=0);mode=iteration%10;result=0 if mode==7 else (255 if mode==8 else 1)
        h.write(owner,rng.randbytes(0x300));h.write(table,bytes(template));h.write(owner+12,struct.pack('<II',table,0x12345678 if iteration%2 else 0))
        h.write(table+44*32+24,struct.pack('<I',stub))
        if mode==6:h.write(table+10*32,b'\0')
        data=bytearray(256);position=0
        def bits(value,width):
            nonlocal position
            for i in range(width):data[position//8]|=((value>>i)&1)<<(position%8);position+=1
        kinds={0:[],1:[],2:[10],3:[0,11,10],4:[45],5:[10],6:[10],7:[44],8:[44],9:[44,10,11]}[mode]
        if mode==1:bits(0x64656267,32)
        for kind in kinds:
            bits(1,1);bits(kind,8);n=12 if kind in [0,10] else 8
            bits(0 if mode==5 else n,16)
            if kind==0:bits(0x1234,16);bits(0xabcdef00,32);bits(1,1)
            elif kind==10:bits(0x1122334455667788,64);bits(3,4)
            elif kind==11:bits(0x1122334455667788,64)
            elif kind==44:bits(0xa5,8)
        bits(0,1)
        capacity=[len(data),0,1,4,8,(position+7)//8][iteration//10%6]
        h.write(wire,bytes(data));h.write(stream,struct.pack('<III',wire,capacity,1))
        incoming=rng.randbytes(0x10008) if iteration%2 else bytes(0x10008);h.write(scratch,incoming)
        def run():
            value=process(h.memory,C.byref(ops),owner,owner+0x100,stream,scratch)
            assert h.read(scratch,8)==bytes(h.u.mem_read(frames['header'],8)),('header scratch',iteration)
            assert h.read(scratch+8,65536)==bytes(h.u.mem_read(frames['payload'],65536)),('payload scratch',iteration)
            C.memmove(h.pointer+scratch-BASE,incoming,len(incoming))
            return value
        h.call('message_reader',0x7afd0,dict(ecx=owner),[owner+0x100,stream],run,255)
        assert original==native,(iteration,original,native)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/message-reader-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/message_reader.c','include/halo2/message_reader.h','src/message_dispatch.c','include/halo2/message_dispatch.h','src/network_messages.c','src/bitstream.c','config/message_descriptors.json','tests/message_reader_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original packet reader, CRT stack probe, header reader and ping/join-refusal/leave decoders intact. Native codec dispatch used. Engine handler 938e0 controlled, plus explicit synthetic decoder cases for raw AL and callback mutation. Debug tag, empty/short streams, multiple messages, invalid headers, disabled descriptors, decoder failure, handler/table changes, scratch and full persistent memory/events compared. Original locals seeded. Handler dispatch itself and live receive I/O remain unimplemented.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
