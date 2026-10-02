#include "halo2/network_bind.h"
#include "internal/memory.h"
#include <string.h>
uint8_t h2_network_socket_bind_bytes(h2_memory *m,const h2_socket_creation_platform *creation,const h2_socket_option_platform *options,const h2_socket_bind_platform *platform,uint32_t socket,const uint8_t address[20],uint8_t workspace[28]) {
    if (!*h2_ptr(m,0x4d8b18,1) || !*h2_ptr(m,0x4d8b19,1)) return 0;
    /* Separate stack-local address storage from the engine's guest arena while
     * retaining the reviewed converter and the incoming stack bytes. */
    uint8_t local[64]={0};
    memcpy(local,workspace,28);memcpy(local+32,address,20);
    h2_memory frame={local,0,sizeof(local)};
    uint8_t converted=h2_network_address_to_sockaddr(&frame,32,0,56);
    memcpy(workspace,local,28);
    if (!converted) return 0;
    uint32_t length=h2_read32(&frame,56);
    if (!h2_network_socket_ensure_handle_for_width(m,creation,options,socket,(uint32_t)address[18]|((uint32_t)address[19]<<8))) return 0;
    if (platform->bind(platform->context,h2_read32(m,socket),workspace,length)) {
        platform->last_error(platform->context);return 0;
    }
    return 1;
}

uint8_t h2_network_socket_bind(h2_memory *m,const h2_socket_creation_platform *creation,const h2_socket_option_platform *options,const h2_socket_bind_platform *platform,uint32_t socket,uint32_t address,uint8_t workspace[28]) {
    if (!*h2_ptr(m,0x4d8b18,1) || !*h2_ptr(m,0x4d8b19,1)) return 0;
    return h2_network_socket_bind_bytes(m,creation,options,platform,socket,h2_ptr(m,address,20),workspace);
}
