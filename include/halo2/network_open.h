#ifndef HALO2_NETWORK_OPEN_H
#define HALO2_NETWORK_OPEN_H
#include "halo2/network_socket.h"
#include "halo2/network_bind.h"
typedef struct {
    h2_socket_platform socket;
    h2_socket_creation_platform creation;
    h2_socket_option_platform options;
    h2_socket_bind_platform binding;
    void *context;
    uint32_t (*ioctl)(void *,uint32_t handle,uint32_t command,uint32_t *value);
} h2_network_open_platform;
uint8_t h2_network_open_endpoint_socket(h2_memory *,const h2_network_open_platform *,uint32_t type,uint32_t port,uint32_t special,uint32_t output,uint8_t bind_workspace[28]); /* 00092ae0 */
#endif
