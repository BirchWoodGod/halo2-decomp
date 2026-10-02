#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE,STACK
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x7c110);stream=h.table;buffer=stream+0x200;desc=stream+0x4000;scratch=stream+0x6000
    validate=h.lib.h2_session_description_valid;validate.argtypes=[C.POINTER(Memory),C.c_uint32];validate.restype=C.c_uint8
    decode=h.lib.h2_session_description_read;decode.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;decode.restype=C.c_uint8
    fields=[(2,2,2),(4,4,5),(8,4,65535),(12,4,65535),(16,2,3),(18,2,3),(20,2,3),
            (0x94,2,17),(0x96,2,17),(0x98,2,17),(0x9a,2,17),(0x9c,2,5),(0x9e,2,10),
            (0xb4,4,3),(0xb8,4,0x80000000),(0xbc,2,17),(0x6e0,4,256),(0xa8,4,4)]
    def valid_fixture():
        data=bytearray(rng.randbytes(0x714))
        for offset,width,limit in fields:data[offset:offset+width]=bytes(width)
        struct.pack_into('<II',data,8,0xffffffff,0xffffffff)
        return data
    h.call('description_valid',0x7b880,dict(eax=0),[],lambda:validate(h.memory,0),255)
    for offset,width,limit in fields:
        for value in [0,1,limit-1,limit,limit+1,(1<<(width*8-1))-1,1<<(width*8-1),(1<<(width*8))-1]:
            data=valid_fixture();data[offset:offset+width]=(value&((1<<(width*8))-1)).to_bytes(width,'little');h.write(desc,bytes(data))
            h.call('description_valid',0x7b880,dict(eax=desc),[],lambda:validate(h.memory,desc),255)
    for first in [0xffffffff,1,65534,65535]:
        for second in [0,1,65534,65535,0x7fffffff,0x80000000,0xffffffff]:
            data=valid_fixture();struct.pack_into('<II',data,8,first,second);h.write(desc,bytes(data))
            h.call('description_valid',0x7b880,dict(eax=desc),[],lambda:validate(h.memory,desc),255)

    import unicorn as U
    from unicorn import x86_const as X
    local_seed={'active':False}
    def seed_locals(u,address,size,ctx):
        if local_seed['active']:
            base=u.reg_read(X.UC_X86_REG_ESP)-(0x4c if address==0x7c110 else 0x140)
            u.mem_write(base,local_seed['incoming']);local_seed['frame']=base
    hooks=[h.u.hook_add(U.UC_HOOK_CODE,seed_locals,begin=a,end=a) for a in [0x7c110,0x7ba10]]
    reply_read=h.lib.h2_message_broadcast_reply_read;reply_read.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4;reply_read.restype=C.c_uint8
    for iteration in range(384):
        start=iteration%32;wire=bytearray(0x1800);position=start
        def bits(value,width):
            nonlocal position
            for i in range(width):
                wire[position//8]|=((value>>i)&1)<<(position%8);position+=1
        def block(data):
            for value in data:bits(value,8)
        # Wire header, including the signed +1 encodings and fixed byte blocks.
        for value,width in [(7,8),(iteration//32%3,2),(2,3),(0,16),(2,16),(1,2),(2,2),(0,2)]:bits(value,width)
        name=[b'Halo\x00',b'\xc3\xa9\x00',b'\xf0\x90\x80\x80\x00',b'\xffA\x00'][iteration%4]
        block(name+bytes(32-len(name)))
        block(rng.randbytes(8+16+36))
        for value,width in [(16,5),(8,5),(1,5),(0,5),(4,3),(9,4),(15,4),(0x12345678,32),(0,3),(0xffffffff,32),(iteration%2,1),(1,2),(9,32)]:bits(value,width)
        count,extra=[(0,0),(1,1),(2,3),(0,2),(16,16),(17,17),(3,2),(1,31)][iteration//4%8]
        bits(count,5);bits(extra,5)
        if count<=extra<=16:
            for player in range(extra):
                block(rng.randbytes(12));text=('Player'+str(player)).encode()+b'\0';block(text+bytes(32-len(text)))
                bits(rng.getrandbits(32),32);bits(player+1,5)
                for value,width in [(1,5),(2,5),(3,5),(4,5),(1,3),(3,6),(4,6),(2,4)]:bits(value,width)
        mask=[0,1,0x55,0xff][iteration//8%4];wire_mask=[0,0xaa,1,0xff][iteration//16%4]
        bits(mask,8);bits(wire_mask,8)
        for i in range(8):
            if wire_mask&(1<<i):bits(0x11223300+i,32)
        present=iteration//2%2;bits(present,1)
        if present:block(rng.randbytes(12))
        capacity=[len(wire),0,8,40,96,120,(position+7)//8,max(0,(position-7)//8)][iteration//32%8]
        h.write(stream,rng.randbytes(0x100));h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<IB',start,1 if iteration%37==0 else 0))
        h.write(buffer,bytes(wire));h.write(desc,rng.randbytes(0x714))
        incoming=bytearray(rng.randbytes(76) if iteration%2 else bytes(76));incoming[43]=incoming[75]=0;incoming=bytes(incoming);h.write(scratch,incoming)
        frame=STACK+0x8000-0x4c;h.u.mem_write(frame,incoming)
        def run():
            result=decode(h.memory,stream,desc,scratch)
            assert h.read(scratch,76)==bytes(h.u.mem_read(frame,76)),('scratch',iteration)
            C.memmove(h.pointer+scratch-BASE,incoming,76)
            return result
        h.call('description_read',0x7c110,dict(eax=stream),[desc],run,255)
        # Prefix the same independently constructed description with its 80-bit
        # broadcast header, retaining the initial bit offset.
        wrapped=(int.from_bytes(wire,'little')<<80).to_bytes(len(wire)+10,'little')
        h.write(buffer,wrapped);h.write(stream+4,struct.pack('<I',capacity+10));h.write(stream+16,struct.pack('<IB',start,1 if iteration%37==0 else 0))
        h.write(desc-12,rng.randbytes(0x720));h.write(scratch,incoming)
        frame=STACK+0x8000-0x60;h.u.mem_write(frame,incoming)
        def run_reply():
            result=reply_read(h.memory,stream,0x720,desc-12,scratch)
            assert h.read(scratch,76)==bytes(h.u.mem_read(frame,76)),('reply scratch',iteration)
            C.memmove(h.pointer+scratch-BASE,incoming,76)
            return result
        local_seed.update(active=True,incoming=incoming)
        h.call('broadcast_reply_read',0xac7a0,{},[stream,0x720,desc-12],run_reply,255)
        local_seed['active']=False

    encode=h.lib.h2_session_description_write;encode.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;encode.restype=None
    reply_write=h.lib.h2_message_broadcast_reply_write;reply_write.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4;reply_write.restype=None
    for wrapper in [False,True]:
        for iteration in range(256):
            data=valid_fixture()
            # Keep input strings terminated while varying their widths and
            # preserving nonzero tails in the fixed-size source name fields.
            name=['Halo','Café','\ud800','X'*31][iteration%4].encode('utf-16le','surrogatepass')+bytes(2)
            data[24:24+len(name)]=name
            for player in range(16):
                name=('Player'+str(player)).encode('utf-16le')+bytes(2)
                at=0x17e+player*64;data[at:at+len(name)]=name
            count=[0,1,2,8,16,0xffff][iteration%6];struct.pack_into('<H',data,0xbc,count)
            struct.pack_into('<I',data,0x6e0,[0,1,0x55,0xff,0x100,0xffffffff][iteration//6%6])
            data[0x704]=[0,1,255][iteration%3]
            if iteration%5==0:struct.pack_into('<H',data,0x10,0xffff)
            h.write(desc-12,rng.randbytes(12)+bytes(data))
            h.write(stream,rng.randbytes(0x100));h.write(buffer,rng.randbytes(0x1800))
            capacity=[0,8,40,96,120,512,1024,0x1800][iteration//3%8];position=iteration%32
            h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<I',position))
            incoming=rng.randbytes(64);h.write(scratch,incoming)
            frame=STACK+0x8000-(0x254 if wrapper else 0x140);h.u.mem_write(frame,incoming)
            def run_write():
                if wrapper:reply_write(h.memory,stream,0xffffffff,desc-12,scratch)
                else:encode(h.memory,stream,desc,scratch)
                assert h.read(scratch,64)==bytes(h.u.mem_read(frame,64)),('writer scratch',wrapper,iteration)
                C.memmove(h.pointer+scratch-BASE,incoming,64)
            local_seed.update(active=True,incoming=incoming)
            if wrapper:h.call('broadcast_reply_write',0xac730,{},[stream,0xffffffff,desc-12],run_write)
            else:h.call('description_write',0x7ba10,dict(ecx=stream),[desc],run_write)
            local_seed['active']=False
    for handle in hooks:h.u.hook_del(handle)


def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/session-description-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/session_description.c','include/halo2/session_description.h','src/text_codec.c','include/halo2/text_codec.h','src/bitstream.c','src/network_messages.c','src/network_config.c','tests/session_description_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original validator and full session-description decoder with all engine callees intact. Field boundaries, first/second ID quirk, count pairs, extra discarded players, masks, optional payload, text, short streams and sticky errors. Original local scratch seeded with zero or nonzero bytes and text terminators; native scratch compared then restored before full persistent-memory comparison. Disjoint stream/payload/scratch. AL compared. Description and broadcast-reply writers include nonzero name tails, signed counts and short buffers. No live discovery.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
