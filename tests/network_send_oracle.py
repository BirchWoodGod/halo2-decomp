#!/usr/bin/env python3
import argparse,ctypes as C,hashlib,json,random,struct
import unicorn as U
from unicorn import x86_const as X
from hash_crc_oracle import Harness
from engine_pools_oracle import BASE
from data_array_oracle import ROOT,Memory,EXPECTED
Send=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint8),C.c_uint32)
Error=C.CFUNCTYPE(C.c_uint32,C.c_void_p)
class Ops(C.Structure):
    _fields_=[('context',C.c_void_p),('send_to',Send),('last_error',Error)]
def suite(h):
    rng=random.Random(0xb5110);socket=h.table;address=socket+32;data=socket+64
    original=[];native=[];result=0;error=0;mutate=False
    def event(read,write,events,kind,args):
        events.append((kind,args,bytes(read(socket,96))))
        if mutate and kind=='send':write(socket,struct.pack('<I',0xaabbccdd))
        return result if kind=='send' else error
    def nw(p,d):C.memmove(h.pointer+p-BASE,d,len(d))
    send_cb=Send(lambda ctx,handle,buf,length,flags,addr,n:event(h.read,nw,native,'send',(handle,buf,length,flags,C.string_at(addr,28),n)))
    error_cb=Error(lambda ctx:event(h.read,nw,native,'error',()))
    ops=Ops(None,send_cb,error_cb)
    def hook(u,at,size,ctx):
        esp=u.reg_read(X.UC_X86_REG_ESP)
        if at==0x3cd254:
            handle,buf,length,flags,addr,n=struct.unpack('<6I',u.mem_read(esp+4,24))
            value=event(u.mem_read,u.mem_write,original,'send',(handle,buf,length,flags,bytes(u.mem_read(addr,28)),n));purge=24
        else:value=event(u.mem_read,u.mem_write,original,'error',());purge=0
        u.reg_write(X.UC_X86_REG_EAX,value);u.reg_write(X.UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(esp,4))[0]);u.reg_write(X.UC_X86_REG_ESP,esp+4+purge)
    for at in [0x3cd254,0x3cd718]:h.u.hook_add(U.UC_HOOK_CODE,hook,begin=at,end=at)
    fn=h.lib.h2_network_socket_send_to;fn.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*3+[C.c_uint16,C.POINTER(C.c_uint8)];fn.restype=C.c_uint16
    for i in range(512):
        width=[0,4,16,0xffff][i%4];active=[(0,1),(1,0),(1,1),(255,255)][i//4%4];length=[0,1,0x7fff,0x8000,0xffff][i//16%5]
        result=[0,1,0x7fff,0x8000,0xffff,0xffffffff,0x1234ffff,0xffff0001][i//3%8];error=[0,0x2733,0x2751,0x2734][i//7%4];mutate=bool(i%2)
        h.write(socket,rng.randbytes(96));h.write(socket,struct.pack('<I',0xffffffff if i%3==0 else 17));h.write(address+18,struct.pack('<H',width));h.write(0x4d8b18,bytes(active))
        initial=rng.randbytes(28);workspace=(C.c_uint8*28).from_buffer_copy(initial);h.u.mem_write(0x2008000-28,initial);original.clear();native.clear()
        h.call('send_to',0xb5110,dict(esi=address),[socket,data,length],lambda:fn(h.memory,C.byref(ops),address,socket,data,length,workspace),0xffff)
        assert original==native
        assert bytes(workspace)==bytes(h.u.mem_read(0x2008000-28,28))

    endpoint=socket+0x1000;connections=socket+0x2000
    find=h.lib.h2_network_endpoint_find_route;find.argtypes=[C.POINTER(Memory)]+[C.c_uint32]*3;find.restype=C.c_uint32
    connection=h.lib.h2_network_endpoint_find_connection;connection.argtypes=find.argtypes;connection.restype=C.c_uint32
    dispatch=h.lib.h2_network_endpoint_send;dispatch.argtypes=[C.POINTER(Memory),C.POINTER(Ops)]+[C.c_uint32]*5+[C.POINTER(C.c_uint8)];dispatch.restype=None
    def setup_routes(width,count):
        h.write(endpoint,rng.randbytes(0x500));h.write(connections,rng.randbytes(0x1000));h.write(address,rng.randbytes(20));h.write(address+18,struct.pack('<H',width))
        h.write(endpoint+0x20,struct.pack('<I',count));h.write(0x4d87d4,struct.pack('<I',connections))
        for j in range(4):
            entry=endpoint+0x24+j*32;h.write(entry,struct.pack('<I',j));h.write(entry+12,h.read(address,20));h.write(connections+j*0xf8+0x54,struct.pack('<I',[0,2,3,8][j]));h.write(connections+j*0xf8+0x48,bytes([0,0x40,0x80,0xc0][j:j+1]))
    for i in range(192):
        width=[0,4,16,20,0xffff][i%5];count=[0,1,2,4,0xffffffff][i//5%5];kind=[0,1,2,3,0xffffffff][i//7%5]
        setup_routes(width,count)
        if i%3==0:h.write(endpoint+0x30,b'\xfe')
        h.call('find_route',0x92e50,dict(ecx=endpoint),[kind,address],lambda:find(h.memory,endpoint,kind,address),0xffffffff)
        h.call('find_connection',0x92ef0,dict(esi=endpoint,ecx=kind,eax=address),[],lambda:connection(h.memory,endpoint,kind,address),0xffffffff)
    for i in range(256):
        setup_routes([4,16,0,0xffff][i//4%4],4);kind=i%4;length=[0,1,127,0xffff,0x10000,0xffffffff][i//3%6]
        for j in range(4):h.write(endpoint+12+j*4,struct.pack('<I',0 if i%11==0 else socket))
        h.write(socket,struct.pack('<I',17));h.write(0x4d8b18,bytes([0 if i%13==0 else 1,1]));result=[0,1,0xffff,0xffffffff][i//5%4];error=[0x2751,0x2733,0][i//7%3];mutate=bool(i%2)
        initial=rng.randbytes(28);workspace=(C.c_uint8*28).from_buffer_copy(initial);h.u.mem_write(0x2008000-72,initial);original.clear();native.clear()
        h.call('endpoint_send',0x93730,dict(ebx=endpoint,edi=kind),[address,length,data],lambda:dispatch(h.memory,C.byref(ops),endpoint,kind,address,length,data,workspace))
        assert original==native
        # Later route lookup reuses this dead stack area; compare its full
        # contents at the send boundary above, not after the parent returns.

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',default='build/libhalo2_engine.so');p.add_argument('--report',default='analysis/network-send-tests.json');a=p.parse_args()
    library=(ROOT/a.library).resolve();h=Harness(library)
    try:suite(h)
    finally:h.close()
    sources=['src/network_routing.c','include/halo2/network_routing.h','src/network_send.c','include/halo2/network_send.h','src/network_address.c','tests/network_send_oracle.py','tests/hash_crc_oracle.py']
    report=dict(passed=True,xbe_sha256=EXPECTED,library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),comparisons=h.counts,total_comparisons=sum(h.counts.values()),source_hashes={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources},scope='Original send wrapper, address converter, route/connection lookups and endpoint send intact; only SDK sendto/error controlled. Full memory, AX, callback arguments/order, converted and untouched stack workspace bytes. Signed 16-bit lengths, low-word errors and callback mutation. No Linux socket backend.')
    (ROOT/a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
