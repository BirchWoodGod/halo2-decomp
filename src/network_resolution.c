#include "halo2/network_resolution.h"
#include "internal/memory.h"
static uint16_t read16(h2_memory *m,uint32_t p) {const uint8_t *b=h2_ptr(m,p,2);return (uint16_t)(b[0]|(uint16_t)b[1]<<8);}
static void write16(h2_memory *m,uint32_t p,uint16_t v) {uint8_t *b=h2_ptr(m,p,2);b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);}
static uint32_t swap32(uint32_t v) {return (v>>24)|((v>>8)&0xff00)|((v<<8)&0xff0000)|(v<<24);}
uint8_t h2_network_address_valid(h2_memory *m,uint32_t address) {
    if (!address) return 0;
    uint16_t width=read16(m,address+18);
    if (width==4 || width==0xffff) return h2_read32(m,address)!=0;
    if (width==16) for (uint32_t i=0;i<8;++i) if (read16(m,address+i*2)) return 1;
    return 0;
}
uint8_t h2_network_address_resolve_key(h2_memory *m,const h2_network_resolution_platform *p,uint32_t index,uint32_t kind,uint32_t output,uint32_t peer,uint16_t port,uint32_t scratch) {
    h2_write32(m,scratch,peer);
    uint32_t key=0x4cf7d4+index*32;
    if (kind || !*h2_ptr(m,key,1) || h2_read32(m,key+4)) return 0;
    if (p->resolve(p->context,peer,key+8,scratch)) return 0;
    h2_write32(m,output,swap32(h2_read32(m,scratch)));
    write16(m,output+16,port);write16(m,output+18,4);
    return h2_network_address_valid(m,output);
}
uint8_t h2_network_address_resolve(h2_memory *m,const h2_network_resolution_platform *p,uint32_t index,uint32_t output,uint32_t peer,uint32_t kind,uint16_t port,uint32_t scratch) {
    if (index!=UINT32_MAX) return h2_network_address_resolve_key(m,p,index,kind,output,peer,port,scratch);
    for (uint32_t i=0;i<8;++i) if (h2_network_address_resolve_key(m,p,i,kind,output,peer,port,scratch)) return 1;
    return 0;
}
uint8_t h2_network_address_prepare(h2_memory *m,const h2_network_resolution_platform *p,uint32_t address,uint32_t scratch) {
    h2_write32(m,scratch,address);
    if (!h2_network_address_registered_ipv4(m,address,scratch)) return 0;
    return p->prepare(p->context,h2_read32(m,scratch))==0;
}
uint8_t h2_network_observer_resolve_address(h2_memory *m,const h2_network_resolution_platform *p,uint32_t observer,uint32_t consumer,uint32_t peer,uint32_t address,uint32_t index_out,uint32_t identity,uint32_t key,uint32_t scratch) {
    uint32_t slot=observer+consumer*36;
    if (h2_read32(m,slot+0x14) && h2_read32(m,slot+0x18)!=UINT32_MAX &&
        h2_network_address_resolve(m,p,h2_read32(m,slot+0x18),scratch,peer,h2_read32(m,slot+0x1c),1000,scratch+20) &&
        h2_network_address_prepare(m,p,scratch,scratch+24)) {
        for (uint32_t i=0;i<5;++i) h2_write32(m,address+i*4,h2_read32(m,scratch+i*4));
        h2_write32(m,index_out,h2_read32(m,slot+0x18));
        h2_write32(m,identity,h2_read32(m,slot+0x20));h2_write32(m,identity+4,h2_read32(m,slot+0x24));
        for (uint32_t i=0;i<4;++i) h2_write32(m,key+i*4,h2_read32(m,slot+0x28+i*4));
        return 1;
    }
    for (uint32_t i=0;i<5;++i) h2_write32(m,address+i*4,0);
    return 0;
}
