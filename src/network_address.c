#include "halo2/network_address.h"
#include "internal/memory.h"
#include <string.h>
static uint32_t read16(h2_memory *m,uint32_t a) {
    const uint8_t *p=h2_ptr(m,a,2);return (uint32_t)p[0]|((uint32_t)p[1]<<8);
}
static void write16(h2_memory *m,uint32_t a,uint32_t v) {
    uint8_t *p=h2_ptr(m,a,2);p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);
}
static uint32_t swap16(uint32_t v) { return ((v&255)<<8)|(v>>8); }
static uint32_t swap32(uint32_t v) { return (v<<24)|((v&0xff00)<<8)|((v>>8)&0xff00)|(v>>24); }
uint8_t h2_network_address_to_sockaddr(h2_memory *m,uint32_t address,uint32_t output,uint32_t length) {
    h2_write32(m,length,0);
    uint32_t kind=read16(m,address+18);
    if (kind==4) {
        write16(m,output,2);
        h2_write32(m,output+4,swap32(h2_read32(m,address)));
        write16(m,output+2,swap16(read16(m,address+16)));
        h2_write32(m,length,16);return 1;
    }
    if (kind==16) {
        write16(m,output,23);
        for (uint32_t i=0;i<16;i+=2) write16(m,output+8+i,swap16(read16(m,address+i)));
        write16(m,output+2,swap16(read16(m,address+16)));
        h2_write32(m,length,28);return 1;
    }
    return 0;
}
uint8_t h2_network_address_from_sockaddr(h2_memory *m,uint32_t input,uint32_t length,uint32_t address) {
    if (length==16) {
        h2_write32(m,address,swap32(h2_read32(m,input+4)));
        uint32_t port=swap16(read16(m,input+2));
        write16(m,address+18,4);write16(m,address+16,port);return 1;
    }
    if (length==28) {
        for (uint32_t i=0;i<16;i+=2) write16(m,address+i,swap16(read16(m,input+8+i)));
        uint32_t port=swap16(read16(m,input+2));
        write16(m,address+18,16);write16(m,address+16,port);return 1;
    }
    memset(h2_ptr(m,address,20),0,20);return 0;
}
uint8_t h2_network_socket_ensure_handle_for_width(h2_memory *m,const h2_socket_creation_platform *platform,const h2_socket_option_platform *options,uint32_t socket,uint32_t length) {
    if (h2_read32(m,socket)==UINT32_MAX) {
        uint32_t kind=read16(m,socket+6),type=0,protocol=0,family=UINT32_MAX;
        if (kind==2) { type=2;protocol=17; }
        else if (kind==3) { type=2;protocol=254; }
        else if (kind==4) { type=1;protocol=6; }
        if (length==4) family=2;
        else if (length==16) family=23;
        uint32_t handle=platform->create(platform->context,family,type,protocol);
        h2_write32(m,socket,handle);
        if (handle==UINT32_MAX) { platform->last_error(platform->context);return 0; }
    }
    if (h2_network_socket_get_option(m,options,socket,4)) *h2_ptr(m,socket+4,1)|=0x10;
    return 1;
}

uint8_t h2_network_socket_ensure_handle(h2_memory *m,const h2_socket_creation_platform *platform,const h2_socket_option_platform *options,uint32_t socket,uint32_t address) {
    uint32_t width=h2_read32(m,socket)==UINT32_MAX ? read16(m,address+18) : 0;
    return h2_network_socket_ensure_handle_for_width(m,platform,options,socket,width);
}

uint8_t h2_network_address_registered_ipv4(h2_memory *m,uint32_t address,uint32_t output) {
    if (!address) return 0;
    uint32_t width=read16(m,address+18);
    if (width==4 || width==0xffff) {
        if (!h2_read32(m,address)) return 0;
    } else if (width==16) {
        uint32_t i=0;
        while (i<8 && !read16(m,address+i*2)) ++i;
        if (i==8) return 0;
    } else return 0;
    if (width!=4) return 0;
    uint32_t value=h2_read32(m,address);
    h2_write32(m,output,swap32(value));
    return !(value>>24);
}
