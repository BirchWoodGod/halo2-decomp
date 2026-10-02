#include "halo2/network_socket.h"
#include "internal/memory.h"
static void reset_socket(h2_memory *m,uint32_t socket) {
    h2_write32(m,socket,UINT32_MAX);
    uint8_t *p=h2_ptr(m,socket+4,2);p[0]=0;p[1]=0;
}
uint32_t h2_network_socket_create(h2_memory *m,const h2_socket_platform *platform,uint32_t type) {
    if (!*h2_ptr(m,0x4d8b18,1) || !*h2_ptr(m,0x4d8b19,1)) return 0;
    uint32_t socket=platform->allocate(platform->context,0,8,0x101000,4);
    if (!socket) { platform->last_error(platform->context,0);return 0; }
    reset_socket(m,socket);
    uint8_t *p=h2_ptr(m,socket+6,2);p[0]=(uint8_t)type;p[1]=(uint8_t)(type>>8);
    return socket;
}
void h2_network_socket_close(h2_memory *m,const h2_socket_platform *platform,uint32_t socket) {
    uint32_t handle=h2_read32(m,socket);
    if (handle!=UINT32_MAX && *h2_ptr(m,0x4d8b18,1) && *h2_ptr(m,0x4d8b19,1)) {
        if (*h2_ptr(m,socket+4,1)&1)
            if (platform->shutdown(platform->context,handle,2)) platform->last_error(platform->context,1);
        if (platform->close(platform->context,h2_read32(m,socket))) platform->last_error(platform->context,1);
    }
    reset_socket(m,socket);
}
void h2_network_endpoint_close(h2_memory *m,const h2_socket_platform *platform,uint32_t endpoint) {
    for (uint32_t i=0;i<4;i++) {
        uint32_t slot=endpoint+0xc+i*4,socket=h2_read32(m,slot);
        if (socket) {
            h2_network_socket_close(m,platform,socket);
            if (!platform->release(platform->context,socket,0,0x8000)) platform->last_error(platform->context,0);
            h2_write32(m,slot,0);
        }
    }
    *h2_ptr(m,endpoint+8,1)=0;
}
