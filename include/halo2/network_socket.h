#ifndef HALO2_NETWORK_SOCKET_H
#define HALO2_NETWORK_SOCKET_H
#include "halo2/memory.h"
/* Explicit SDK/kernel boundary. Guest handles and allocation flags retain their
 * Xbox meanings; these are not POSIX function signatures. */
typedef struct {
    void *context;
    uint32_t (*allocate)(void *,uint32_t address,uint32_t size,uint32_t type,uint32_t protection);
    uint32_t (*release)(void *,uint32_t address,uint32_t size,uint32_t type);
    uint32_t (*shutdown)(void *,uint32_t handle,uint32_t how);
    uint32_t (*close)(void *,uint32_t handle);
    void (*last_error)(void *,uint32_t socket_error);
} h2_socket_platform;
uint32_t h2_network_socket_create(h2_memory *,const h2_socket_platform *,uint32_t type); /* 000b4d50 */
void h2_network_socket_close(h2_memory *,const h2_socket_platform *,uint32_t socket); /* 000b4f50 */
void h2_network_endpoint_close(h2_memory *,const h2_socket_platform *,uint32_t endpoint); /* 00092c70 */
#endif
