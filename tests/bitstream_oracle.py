#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
from hash_crc_oracle import Harness
from data_array_oracle import ROOT,Memory,EXPECTED

def suite(h):
    rng=random.Random(0x195720);stream=h.table;buffer=stream+0x200
    read=h.lib.h2_bitstream_read_bits;read.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint32];read.restype=C.c_uint32
    write=h.lib.h2_bitstream_write_bits;write.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;write.restype=None
    cases=[(pos,count,16,False) for pos in range(32) for count in range(34)]
    cases += [(rng.choice([0,1,7,8,31,32,63,64,127,0xffffffe0,0xffffffff]),rng.choice([0,1,7,31,32,33,64,0xffffffff,0x80000000]),rng.choice([0,1,3,4,7,8,16,0x20000000,0x40000000]),False) for _ in range(400)]
    # Buffers overlapping the stream verify reloads after a word store.
    cases += [(pos,count,8,True) for pos in [0,1,31,32,33,63] for count in [0,1,2,31,32]]
    for pos,count,size,alias in cases:
        fixture=rng.randbytes(0x400);value=rng.getrandbits(32)
        for mode in ['read','write']:
            h.write(stream-0x40,fixture)
            data=stream+0x10 if alias else buffer
            h.write(stream,struct.pack('<II',data,size));h.write(stream+0x10,struct.pack('<I',pos))
            if mode=='read':h.call('read_bits',0x1959c0,dict(edi=stream),[count],lambda:read(h.memory,stream,count),0xffffffff)
            else:h.call('write_bits',0x195720,dict(eax=stream,edx=value),[count],lambda:write(h.memory,stream,value,count))

    pop=h.lib.h2_bitstream_pop_checkpoint;pop.argtypes=[C.POINTER(Memory),C.c_uint32,C.c_uint8];pop.restype=None
    for iteration in range(512):
        h.write(stream-0x40,rng.randbytes(0x400))
        depth=1+iteration%4;saved=[0,1,7,8,15,31,32,63,64,65,0xffffffff,0xfffffff8][iteration%12]
        current=[0,1,8,32,64,128,0xffffffff,0x80000000][iteration//4%8]
        size=[0,1,4,8,16][iteration//8%5];mode=[0,1,2,3,4][iteration//3%5];rollback=[0,1,255][iteration//7%3]
        h.write(stream,struct.pack('<II',buffer,size));h.write(stream+0xc,struct.pack('<II',mode,current));h.write(stream+0x18,struct.pack('<I',depth));h.write(stream+0x1c+(depth-1)*4,struct.pack('<I',saved));h.write(stream+0x30,struct.pack('<I',0xffffffff if iteration%2 else 0))
        h.call('pop_checkpoint',0x194710,dict(esi=stream),[rollback],lambda:pop(h.memory,stream,rollback))

    error=h.lib.h2_bitstream_has_error;error.argtypes=[C.POINTER(Memory),C.c_uint32];error.restype=C.c_uint8
    encode=h.lib.h2_message_header_write;encode.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;encode.restype=None
    decode=h.lib.h2_message_header_read;decode.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*4;decode.restype=C.c_uint8
    table=stream+0x1000;type_out=stream+0x800;size_out=type_out+4
    for iteration in range(128):
        h.write(stream,rng.randbytes(0x400));h.write(stream,struct.pack('<II',buffer,[0,1,2,3,4,16][iteration%6]));h.write(stream+0x10,struct.pack('<I',iteration%32))
        kind=[0,44,45,255,256,0x7fffffff,0xffffffff][iteration%7];size=[0,1,65535,65536,0xffffffff][iteration%5]
        h.call('header_write',0x937e0,dict(ebx=stream,edi=kind),[size],lambda:encode(h.memory,stream,kind,size))
    for iteration in range(320):
        h.write(stream,rng.randbytes(0x900));h.write(table,rng.randbytes(45*32))
        kind=[0,1,44,45,255][iteration%5];size=[0,1,12,65535][iteration//5%4];position=iteration%32
        h.write(buffer,((kind|(size<<8))<<position).to_bytes(8,'little'))
        h.write(stream,struct.pack('<II',buffer,[0,1,2,3,4,8][iteration//3%6]));h.write(stream+0x10,struct.pack('<IB',position,1 if iteration%7==0 else 0))
        if kind<45:
            h.write(table+kind*32,bytes([0 if iteration%11==0 else 1]));h.write(table+kind*32+12,struct.pack('<II',[0,1,size,0xffffffff][iteration%4],[0,size,65535,0x80000000][iteration//4%4]))
        out1=[type_out,stream+0x10,stream+4][iteration//13%3]
        out2=[size_out,type_out,stream+0x14,table+12][iteration//17%4]
        h.call('header_read',0x93860,dict(ecx=stream,eax=out1),[table,out2],lambda:decode(h.memory,stream,out1,table,out2),255)
    for iteration in range(128):
        size=[0,1,4,0x10000000,0x20000000,0xffffffff][iteration%6];position=[0,1,32,33,0x7fffffff,0x80000000,0xffffffff][iteration%7]
        h.write(stream+4,struct.pack('<I',size));h.write(stream+0x10,struct.pack('<IB',position,[0,1,255][iteration%3]))
        h.call('has_error',0x1946f0,dict(ecx=stream),[],lambda:error(h.memory,stream),255)

    bulk_read=h.lib.h2_bitstream_read_buffer;bulk_read.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;bulk_read.restype=None
    bulk_write=h.lib.h2_bitstream_write_buffer;bulk_write.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;bulk_write.restype=None
    bulk_cases=[(pos,width,16,0x100) for pos in range(32) for width in [0,1,7,8,9,31,32,33,63,64,65]]
    bulk_cases += [(pos,width,size,offset) for pos in [0,1,7,8,31,32,63,127] for width in [1,32,64] for size,offset in [(0,0),(1,4),(8,-4),(16,1)]]
    for pos,width,size,offset in bulk_cases:
        fixture=rng.randbytes(0x600)
        for mode in ['read','write']:
            h.write(stream-0x40,fixture);h.write(stream,struct.pack('<II',buffer,size));h.write(stream+0x10,struct.pack('<I',pos));other=buffer+offset
            if mode=='read':h.call('read_buffer',0x195820,dict(ebx=stream),[other,width],lambda:bulk_read(h.memory,stream,other,width))
            else:h.call('write_buffer',0x1955d0,dict(edx=stream,eax=other),[width],lambda:bulk_write(h.memory,stream,other,width))

    refuse_write=h.lib.h2_message_join_refuse_write;refuse_write.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;refuse_write.restype=None
    refuse_read=h.lib.h2_message_join_refuse_read;refuse_read.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;refuse_read.restype=C.c_uint8
    payload=buffer+0x100
    for iteration in range(160):
        fixture=rng.randbytes(0x600);size=[0,1,8,9,16][iteration//3%5];pos=iteration%32
        for mode in ['read','write']:
            h.write(stream,fixture);h.write(stream,struct.pack('<II',buffer,size));h.write(stream+0x10,struct.pack('<IB',pos,1 if iteration%13==0 else 0))
            h.write(payload+8,struct.pack('<I',[0,1,15,16,0xffffffff][iteration%5]));ignored=[0,12,0xffffffff][iteration%3]
            if mode=='write':h.call('join_refuse_write',0xad230,{},[stream,ignored,payload],lambda:refuse_write(h.memory,stream,ignored,payload))
            else:h.call('join_refuse_read',0xad290,{},[stream,ignored,payload],lambda:refuse_read(h.memory,stream,ignored,payload),255)

    # Session control and handoff descriptors share these five original bodies.
    for name,address in [('session_id_write',0xad5a0),('leave_read',0xad2e0),
                         ('session_control_read',0xad3f0),('handoff_write',0xad320),('handoff_read',0xad390)]:
        fn=getattr(h.lib,'h2_message_'+name)
        fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3
        reading=name.endswith('read');fn.restype=C.c_uint8 if reading else None
        for iteration in range(192):
            h.write(stream,rng.randbytes(0x600))
            capacity=[0,1,8,9,44,45,64,128][iteration//3%8];position=iteration%32
            h.write(stream,struct.pack('<II',buffer,capacity))
            h.write(stream+16,struct.pack('<IB',position,255 if iteration%17==0 else 0))
            target=buffer+[0x100,0,1,-4][iteration//32%4]
            h.write(target+44,struct.pack('<H',[0,1,15,16,0x7fff,0x8000,0xffff][iteration%7]))
            ignored=[0,8,46,0xffffffff][iteration%4]
            h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,stream,ignored,target),255 if reading else None)

    boolean=h.lib.h2_bitstream_read_bool
    boolean.argtypes=[C.POINTER(Memory),C.c_uint32];boolean.restype=C.c_uint8
    for iteration in range(256):
        h.write(stream,rng.randbytes(0x600))
        capacity=[0,1,4,8,16,0x20000000,0x40000000,0xffffffff][iteration//32%8]
        position=[0,1,7,8,31,32,63,64,127,128,129,0xffffffff,0xfffffff8][iteration%13]
        h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<I',position))
        h.call('read_bool',0x1957d0,dict(edi=stream),[],lambda:boolean(h.memory,stream),255)
    for name,address in [('join_abort_write',0xad1c0),('join_abort_read',0xad1e0),
                         ('host_decline_write',0xad430),('host_decline_read',0xad530)]:
        fn=getattr(h.lib,'h2_message_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3
        reading=name.endswith('read');fn.restype=C.c_uint8 if reading else None
        for iteration in range(320):
            h.write(stream,rng.randbytes(0x600))
            capacity=[0,1,8,9,16,17,44,45,64,128][iteration//3%10];position=iteration%32
            h.write(stream,struct.pack('<II',buffer,capacity))
            h.write(stream+16,struct.pack('<IB',position,255 if iteration%17==0 else 0))
            target=buffer+[0x100,0,1,-4,4][iteration//32%5]
            h.write(target+8,bytes(([0,1,255][iteration%3],[0,1,255][iteration//3%3],[0,1,255][iteration//9%3])))
            if reading:
                # Cover every wire flag combination, including absent fields.
                data=bytearray(h.read(buffer,64));flags=iteration%8
                for bit in range(3):
                    pos=position+64+bit
                    data[pos//8]=(data[pos//8]&~(1<<(pos%8)))|(((flags>>bit)&1)<<(pos%8))
                h.write(buffer,bytes(data))
            ignored=[0,16,48,0xffffffff][iteration%4]
            h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,stream,ignored,target),255 if reading else None)

    def wire_bits(data,position,value,width):
        for bit in range(width):
            pos=position+bit
            data[pos//8]=(data[pos//8]&~(1<<(pos%8)))|(((value>>bit)&1)<<(pos%8))
    for name,address in [('election_write',0xad5c0),('election_read',0xad710),
                         ('election_refuse_write',0xad820),('election_refuse_read',0xad8d0)]:
        fn=getattr(h.lib,'h2_message_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3
        reading=name.endswith('read');fn.restype=C.c_uint8 if reading else None
        refusal='refuse' in name
        for iteration in range(512):
            h.write(stream,rng.randbytes(0x2400))
            capacity=[0,8,9,45,92,96,192,256,512,1024][iteration//3%10];position=iteration%32
            h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<IB',position,255 if iteration%29==0 else 0))
            target=buffer+0x1000
            if refusal:
                target=buffer+[0x1000,0,1,-4][iteration//32%4]
                reason=[0,1,10,11,15,16,0xffffffff][iteration%7]
                flag=[0,1,255][iteration//7%3]
                h.write(target+8,struct.pack('<I',reason));h.write(target+12,bytes([flag]))
                if reading:
                    data=bytearray(h.read(buffer,128));wire_bits(data,position+64,iteration%16,4)
                    wire_bits(data,position+68,iteration//16%2,1);h.write(buffer,bytes(data))
            else:
                count=[0,1,2,8,15,16,17,31,32,0xffffffff][iteration%10]
                mask=[0,1,0xffff,0x10000,0xffffffff][iteration//10%5]
                h.write(target+84,struct.pack('<I',[0,15,16,0xffffffff][iteration%4]))
                h.write(target+92,struct.pack('<I',count))
                h.write(target+192,struct.pack('<II',mask,mask^0xffff if iteration%3 else mask))
                if reading:
                    count=iteration%32
                    data=bytearray(h.read(buffer,1024));wire_bits(data,position+708,count,5)
                    end=position+713+(48*count if count<=16 else 0)
                    wire_bits(data,end,mask,16);wire_bits(data,end+16,mask^0xffff if iteration%3 else mask,16)
                    h.write(buffer,bytes(data))
            ignored=[0,52,200,0xffffffff][iteration%4]
            h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,stream,ignored,target),255 if reading else None)

    # Only the SDK clock is replaced; lookup and every engine codec callee run.
    import unicorn as U
    from unicorn import x86_const as X
    from engine_pools_oracle import BASE
    from network_state_oracle import Operations, Ticks, Provider
    sessions=stream+0x8000;session_base=stream+0x10000;target=stream+0x3000
    original=[];native=[];clock_value=0;mutating=False
    def nw(address,data):C.memmove(h.pointer+address-BASE,data,len(data))
    def tick(read,write,events):
        events.append((bytes(read(target,28)),bytes(read(sessions,12))))
        if mutating:
            for j in range(3):write(session_base+j*0x8000+0x78b0,struct.pack('<I',0xfffffff0+j))
            write(sessions,bytes(12));write(target+8,struct.pack('<I',0xabcdef12))
        return clock_value
    callback=Ticks(lambda ctx:tick(h.read,nw,native));ops=Operations(None,callback,Provider())
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP);value=tick(u.mem_read,u.mem_write,original)
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4)
    handle=h.u.hook_add(U.UC_HOOK_CODE,hook,begin=0x3314b0,end=0x3314b0)
    lookup=h.lib.h2_message_session_lookup;lookup.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*2;lookup.restype=C.c_uint32
    timer=h.lib.h2_message_session_time;timer.argtypes=[C.POINTER(Memory),C.POINTER(Operations),C.c_uint32];timer.restype=C.c_uint32
    for name,address in [('session_lookup',0x75800),('session_time',0x758c0),('time_sync_write',0xad940),('time_sync_read',0xad9e0),('time_sync_clear',0xada90)]:
        fn=getattr(h.lib,'h2_message_'+name)
        if name.startswith('time_sync'):
            fn.argtypes=[C.POINTER(Memory)]+([] if name.endswith('clear') else [C.POINTER(Operations)])+[C.c_uint32]*3
            fn.restype=None if name.endswith('write') else C.c_uint8
        for iteration in range(256):
            original.clear();native.clear();mutating=iteration%3==0;clock_value=[0,1,1000,0xfffffff8,0xffffffff][iteration%5]
            h.write(stream,rng.randbytes(0x4000));h.write(session_base,bytes(0x18000))
            identity=rng.randbytes(8);h.write(target,identity)
            for j in range(3):
                session=session_base+j*0x8000
                h.write(sessions+j*4,struct.pack('<I',0 if iteration%19==0 else session))
                h.write(session+0x1c,identity if j>=iteration%4 else rng.randbytes(8))
                h.write(session+0x24,bytes([0 if iteration%11==0 else 255]))
                h.write(session+0x741c,struct.pack('<I',0 if iteration%13==0 else 5))
                h.write(session+0x78ac,bytes([0 if iteration%7==0 else 1]))
                h.write(session+0x78b0,struct.pack('<I',0xfffffff0 if iteration%2 else 700))
            h.write(0x510550,struct.pack('<I',0 if iteration%17==0 else sessions))
            position=iteration%32;capacity=[0,8,9,12,13,20,21,64][iteration//4%8]
            h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<IB',position,255 if iteration%23==0 else 0))
            h.write(target+24,struct.pack('<H',[0,1,2,0xffff][iteration%4]))
            data=bytearray(h.read(buffer,64));wire_bits(data,position,int.from_bytes(identity,'little'),64);wire_bits(data,position+64,iteration%2,1);h.write(buffer,bytes(data))
            ignored=[0,28,0xffffffff][iteration%3]
            if name=='session_lookup':h.call(name,address,dict(ebx=sessions),[target],lambda:lookup(h.memory,sessions,target),0xffffffff)
            elif name=='session_time':h.call(name,address,dict(eax=target),[],lambda:timer(h.memory,C.byref(ops),target),0xffffffff)
            elif name.endswith('clear'):h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,stream,ignored,target),255)
            else:h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,C.byref(ops),stream,ignored,target),None if name.endswith('write') else 255)
            assert original==native,(name,iteration,original,native)
    h.u.hook_del(handle)

    for name,address in [('connect_request_write',0xac8a0),('connect_request_read',0xac900),
                         ('connect_refuse_write',0xac940),('connect_refuse_read',0xac9a0),
                         ('connect_establish_write',0xac9e0),('connect_establish_read',0xaca00),
                         ('connect_closed_write',0xaca40),('connect_closed_read',0xacab0)]:
        fn=getattr(h.lib,'h2_message_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3
        reading=name.endswith('read');fn.restype=C.c_uint8 if reading else None
        for iteration in range(256):
            h.write(stream,rng.randbytes(0x800))
            capacity=[0,1,4,5,8,9,16,128][iteration//3%8];position=iteration%32
            h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<IB',position,255 if iteration%19==0 else 0))
            target=buffer+[0x100,0,1,-4][iteration//32%4]
            h.write(target+4,struct.pack('<I',[0,7,8,31,32,255,256,0xffffffff][iteration%8]))
            h.write(target+8,struct.pack('<I',[0,17,18,31,32,0xffffffff][iteration%6]))
            if reading:
                data=bytearray(h.read(buffer,64))
                wire_bits(data,position+32,iteration%256,8)
                wire_bits(data,position+64,iteration%32,5);h.write(buffer,bytes(data))
            ignored=[0,8,12,0xffffffff][iteration%4]
            h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,stream,ignored,target),255 if reading else None)

    for name,address in [('ping_write',0xac490),('ping_read',0xac530),
                         ('pong_write',0xac580),('pong_read',0xac610),
                         ('broadcast_search_write',0xac670),('broadcast_search_read',0xac6e0)]:
        fn=getattr(h.lib,'h2_message_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3
        reading=name.endswith('read');fn.restype=C.c_uint8 if reading else None
        for iteration in range(256):
            h.write(stream,rng.randbytes(0x800))
            capacity=[0,1,4,6,7,10,11,128][iteration//3%8];position=iteration%32
            h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<IB',position,255 if iteration%19==0 else 0))
            target=buffer+[0x100,0,1,-4][iteration//32%4]
            h.write(target,struct.pack('<H',[0,1,0x7fff,0x8000,0xffff][iteration%5]))
            h.write(target+8,struct.pack('<I',[0,1,2,3,4,255,256,0xffffffff][iteration%8]))
            if reading:
                data=bytearray(h.read(buffer,64));wire_bits(data,position+48,iteration%4,2);h.write(buffer,bytes(data))
            ignored=[0,12,0xffffffff][iteration%3]
            h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,stream,ignored,target),255 if reading else None)

    for name,address in [('config_fields_write',0x7ee10),('config_fields_read',0x7efa0)]:
        fn=getattr(h.lib,'h2_message_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*2
        reading=name.endswith('read');fn.restype=C.c_uint8 if reading else None
        for iteration in range(384):
            h.write(stream,rng.randbytes(0x800));position=iteration%32
            h.write(stream,struct.pack('<II',buffer,[0,1,4,5,6,16][iteration//3%6]));h.write(stream+16,struct.pack('<I',position))
            target=buffer+[0x100,0,1,-4][iteration//32%4]
            if iteration%3==0:h.write(target,bytes([0xff,0,15,30,6,63,64,15])+rng.randbytes(8))
            if reading:h.call(name,address,dict(eax=stream,esi=target),[],lambda:fn(h.memory,stream,target),255)
            else:h.call(name,address,dict(ebx=stream),[target],lambda:fn(h.memory,stream,target))
    character=h.lib.h2_text_encode_character;character.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;character.restype=C.c_uint32
    encode_text=h.lib.h2_text_encode_string;encode_text.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;encode_text.restype=None
    decode_text=h.lib.h2_text_decode_string;decode_text.argtypes=encode_text.argtypes;decode_text.restype=None
    source=stream+0x800;destination=stream+0xc00
    for value in [0,1,0x7f,0x80,0x7ff,0x800,0xd800,0xdfff,0xffff,0x10000,0x10ffff,0x1fffff,0x200000,0xffffffff]:
        for capacity in [0,1,2,3,4,5,32,0xffffffff,0x80000000]:
            h.write(destination,rng.randbytes(128))
            h.call('text_encode_character',0x1405a0,dict(eax=destination,edi=value),[capacity],lambda:character(h.memory,destination,value,capacity),0xffffffff)
    wide_cases=[[],[0x41],[0x7f,0x80,0x7ff,0x800,0xffff],[0xd800,0xdc00],[0x1234]*40]
    wide_cases += [[rng.randrange(1,65536) for _ in range(rng.randrange(1,40))] for _ in range(30)]
    for words in wide_cases:
        for capacity in [0,1,2,3,4,7,16,31,32,64,128,0xffffffff]:
            h.write(source,bytes(512));h.write(source,struct.pack('<'+'H'*(len(words)+1),*words,0));h.write(destination,rng.randbytes(512))
            h.call('text_encode_string',0x140650,dict(eax=source),[destination,capacity],lambda:encode_text(h.memory,source,destination,capacity))
    byte_cases=[b'',b'abc',bytes.fromhex('c080 c1bf e08080 eda080 f0808080 f4908080 f7bfbfbf'),bytes.fromhex('80 bf ff fe f8 c2 41 e1 80 42 f1 80 80 43'),bytes.fromhex('e180'),bytes.fromhex('f18080'),b'x'*70]
    byte_cases += [bytes(rng.randrange(1,256) for _ in range(rng.randrange(1,40))) for _ in range(30)]
    for data in byte_cases:
        for capacity in [0,1,2,3,4,7,16,31,32,64,128,0xffffffff]:
            h.write(source,bytes(512));h.write(source,data);h.write(destination,rng.randbytes(512))
            h.call('text_decode_string',0x140440,{},[source,destination,capacity],lambda:decode_text(h.memory,source,destination,capacity))

    for reading,address in [(False,0xacc20),(True,0xacfa0)]:
        name='join_request_read' if reading else 'join_request_write'
        fn=getattr(h.lib,'h2_message_'+name);fn.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;fn.restype=C.c_uint8 if reading else None
        for iteration in range(512):
            target=stream+0x2400;h.write(stream,rng.randbytes(0x3000))
            position=iteration%32;capacity=[0,1,61,62,63,64,96,128,512,1024][iteration//3%10]
            h.write(stream,struct.pack('<II',buffer,capacity));h.write(stream+16,struct.pack('<IB',position,255 if iteration%29==0 else 0))
            count=[0,1,15,16,17,31,32,0xffffffff][iteration%8]
            h.write(target+12,struct.pack('<I',count));h.write(target+0x158,bytes([0 if iteration%3==0 else 255]))
            h.write(target+0x160,struct.pack('<I',[0,1,2,3,6,0xffffffff][iteration//2%6]))
            for i in range(16):
                h.write(target+0xd0+i*4,struct.pack('<I',[0,254,255,0xffffffff][iteration%4]))
                h.write(target+0x110+i*4,struct.pack('<I',[0,0x7ffffffe,0x7fffffff,0xffffffff][iteration//4%4]))
            if iteration%2==0:h.write(target+0x180,h.read(0x440070,12))
            if reading:
                data=bytearray(rng.randbytes(0x1000));cursor=position+496;count=iteration//4%32
                wire_bits(data,cursor,count,5);cursor+=5
                for player in range(count):
                    cursor+=96
                    wire_bits(data,cursor,[0,1,255][player%3],8);cursor+=8
                    wire_bits(data,cursor,[0,1,0x7fffffff][player%3],31);cursor+=31
                flag=iteration%2;wire_bits(data,cursor,flag,1);cursor+=1
                if flag:wire_bits(data,cursor,0x12345678,32);cursor+=32
                mode=iteration//2%4;wire_bits(data,cursor,mode,2);cursor+=2
                if mode==2:
                    for value in [0,127,55]:wire_bits(data,cursor,value,7);cursor+=7
                    cursor+=128;present=iteration//8%2;wire_bits(data,cursor,present,1)
                h.write(buffer,bytes(data))
            ignored=[0,0x1b8,0xffffffff][iteration%3]
            h.call(name,address,{},[stream,ignored,target],lambda:fn(h.memory,stream,ignored,target),255 if reading else None)

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/bitstream-tests.json');args=p.parse_args()
    library=(ROOT/args.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/text_codec.c','include/halo2/text_codec.h','src/network_config.c','include/halo2/network_config.h','src/network_messages.c','include/halo2/network_messages.h','src/bitstream.c','include/halo2/bitstream.h','tests/bitstream_oracle.py','tests/hash_crc_oracle.py','tests/network_state_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Unmodified original word/bulk bit I/O, join-refusal, session-control, handoff, join-abort and host-decline and election codecs, boolean reads, checkpoint pop, error and message-header instructions; bulk overlaps and partial words included; original CRT formatting runs on oversized header values. Header outputs include aliases. Rollback/non-rollback, stream modes, saved/current positions, counters and buffer clearing. Full memory and reader EAX; every bit alignment, short/empty buffers, nonzero data, boundary crossing, signed/wrapped counts and buffer/header aliasing. Word padding supplied. Time-sync codecs include original session lookup/time helpers and controlled SDK ticks with callback mutation. Connection request/refusal/establish/closed codecs include overlaps and all closed-reason values. Ping/pong/search codecs preserve padding and validate pong values. Compact configuration codecs and original permissive text conversion are compared; string source/output buffers are disjoint. Join requests include all wire counts, overlapping record fields, mode-specific data and absent optionals. No complete message serialization or real network clock.')
    (ROOT/args.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
