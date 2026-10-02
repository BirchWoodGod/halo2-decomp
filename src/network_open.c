#include "halo2/network_open.h"
#include "internal/memory.h"
uint8_t h2_network_open_endpoint_socket(h2_memory *m,const h2_network_open_platform *ops,uint32_t type,uint32_t port,uint32_t special,uint32_t output,uint8_t workspace[28]) {
    uint32_t socket=h2_network_socket_create(m,&ops->socket,type);
    if (!socket) return 0;
    /* Only the IPv4 word, port, and width are consumed by the recovered bind
     * path. The unused engine-address bytes are initialized for native C. */
    uint8_t address[20]={0};address[16]=(uint8_t)port;address[17]=(uint8_t)(port>>8);address[18]=4;
    uint8_t success=h2_network_socket_bind_bytes(m,&ops->creation,&ops->options,&ops->binding,socket,address,workspace);
    if (success && *h2_ptr(m,0x4d8b18,1) && *h2_ptr(m,0x4d8b19,1)) {
        uint32_t handle=h2_read32(m,socket);
        if (handle==UINT32_MAX) success=0;
        else if (*h2_ptr(m,socket+4,1)&0x10) {
            uint32_t value=1;
            if (ops->ioctl(ops->context,handle,0x8004667e,&value)) {
                ops->socket.last_error(ops->socket.context,1);success=0;
            } else *h2_ptr(m,socket+4,1)&=(uint8_t)~0x10;
        }
    }
    if (success && (special&255)) success=h2_network_socket_set_option(m,&ops->options,socket,2,1);
    if (success) { h2_write32(m,output,socket);return 1; }
    h2_network_socket_close(m,&ops->socket,socket);
    if (!ops->socket.release(ops->socket.context,socket,0,0x8000)) ops->socket.last_error(ops->socket.context,0);
    return 0;
}
