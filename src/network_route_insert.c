#include "halo2/network_route_insert.h"
#include "halo2/network_routing.h"
#include "internal/memory.h"
uint8_t h2_network_endpoint_insert_route(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,const h2_network_storage_operations *storage_ops,uint32_t endpoint,uint32_t index,uint32_t sequence,uint32_t address,uint32_t local,uint32_t packet,uint32_t storage_scratch,uint8_t workspace[28]) {
    uint32_t connection=h2_read32(m,0x4d87d4)+index*0xf8;
    uint32_t state=h2_read32(m,connection+0x54),kind=0;
    if (state>2 && !(state&0x80000000u)) {
        uint8_t flags=*h2_ptr(m,connection+0x48,1);
        if (flags&0x80) kind=1;
        else if (flags&0x40) kind=2;
    }
    uint32_t route=h2_network_endpoint_find_route(m,endpoint,kind,address);
    uint32_t previous=route==UINT32_MAX ? UINT32_MAX : h2_read32(m,endpoint+0x24+route*32);
    if (previous==index) return 1;
    if (previous!=UINT32_MAX) {
        uint32_t old=h2_read32(m,0x4d87d4)+previous*0xf8;
        if (h2_read32(m,connection+0x4c)==h2_read32(m,old+0x4c)) return 0;
        h2_network_connection_dispose(m,clock,send,codec,callbacks,storage_ops,old,local,packet,storage_scratch,workspace);
    }
    uint32_t count=h2_read32(m,endpoint+0x20);
    if (!(count&0x80000000u) && count>=16) return 0;
    h2_write32(m,endpoint+0x24+count*32,index);
    h2_write32(m,endpoint+0x28+h2_read32(m,endpoint+0x20)*32,sequence);
    *h2_ptr(m,endpoint+0x2c+h2_read32(m,endpoint+0x20)*32,1)=0;
    uint32_t destination=endpoint+0x30+h2_read32(m,endpoint+0x20)*32;
    for (uint32_t i=0;i<20;i+=4) h2_write32(m,destination+i,h2_read32(m,address+i));
    h2_write32(m,endpoint+0x20,h2_read32(m,endpoint+0x20)+1);
    return 1;
}
