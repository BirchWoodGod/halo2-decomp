#include "halo2/network_routing.h"
#include "internal/memory.h"
#include <string.h>
uint32_t h2_network_endpoint_find_route(h2_memory *m, uint32_t endpoint, uint32_t kind, uint32_t address) {
    uint32_t count = h2_read32(m,endpoint+0x20);
    if (!count || (count & 0x80000000u)) return UINT32_MAX;
    const uint8_t *a = h2_ptr(m,address+18,2);
    uint32_t width = a[0] | (uint32_t)a[1]<<8;
    for (uint32_t i=0; i<count; ++i) {
        uint32_t entry = endpoint+0x24+i*32;
        const uint8_t *b = h2_ptr(m,entry+30,2);
        if (!width || (width & 0x8000) || width != (b[0] | (uint32_t)b[1]<<8)) continue;
        if (memcmp(h2_ptr(m,address,width),h2_ptr(m,entry+12,width),width)) continue;
        uint32_t connection = h2_read32(m,0x4d87d4)+h2_read32(m,entry)*0xf8;
        if (kind==1 || kind==2) {
            uint32_t state=h2_read32(m,connection+0x54);
            if (state<=2 || (state&0x80000000u)) continue;
            if (!(*h2_ptr(m,connection+0x48,1) & (kind==1 ? 0x80 : 0x40))) continue;
        }
        return i;
    }
    return UINT32_MAX;
}
uint32_t h2_network_endpoint_find_connection(h2_memory *m, uint32_t endpoint, uint32_t kind, uint32_t address) {
    uint32_t index=h2_network_endpoint_find_route(m,endpoint,kind,address);
    return index==UINT32_MAX ? index : h2_read32(m,endpoint+0x24+index*32);
}
void h2_network_endpoint_send(h2_memory *m, const h2_socket_send_platform *ops, uint32_t endpoint,
    uint32_t kind, uint32_t address, uint32_t size, uint32_t data, uint8_t workspace[28]) {
    uint8_t local[20];memcpy(local,h2_ptr(m,address,20),20);
    static const uint16_t ports[]={1000,1005,1006,1001};
    if (kind>=4) abort();
    local[16]=(uint8_t)ports[kind];local[17]=(uint8_t)(ports[kind]>>8);
    uint32_t socket=h2_read32(m,endpoint+12+kind*4);
    if (!socket) return;
    uint16_t result=h2_network_socket_send_to_bytes(m,ops,local,socket,data,(uint16_t)size,workspace);
    uint32_t signed_result=result&0x8000 ? (uint32_t)result|0xffff0000u : result;
    if (signed_result==size || result!=0xffff) return;
    uint32_t index=h2_network_endpoint_find_route(m,endpoint,kind,address);
    if (index!=UINT32_MAX) *h2_ptr(m,endpoint+0x2c+index*32,1)=1;
}

uint8_t h2_network_endpoint_remove_route(h2_memory *m,uint32_t endpoint,uint32_t connection) {
    uint32_t count=h2_read32(m,endpoint+0x20);
    if (!count || (count&0x80000000u)) return 0;
    for (uint32_t i=0;i<count;++i) {
        if (h2_read32(m,endpoint+0x24+i*32)!=connection) continue;
        uint32_t last=count-1;
        h2_write32(m,endpoint+0x20,last);
        if (i<last) {
            uint32_t source=endpoint+0x24+last*32,destination=endpoint+0x24+i*32;
            for (uint32_t j=0;j<32;j+=4) h2_write32(m,destination+j,h2_read32(m,source+j));
        }
        return 1;
    }
    return 0;
}
