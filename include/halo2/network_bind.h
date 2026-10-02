#ifndef HALO2_NETWORK_BIND_H
#define HALO2_NETWORK_BIND_H
#include "halo2/network_address.h"
typedef struct {
    void *context;
    uint32_t (*bind)(void *,uint32_t handle,const uint8_t *address,uint32_t length);
    void (*last_error)(void *);
} h2_socket_bind_platform;
/* workspace represents the original 28-byte stack local. The caller supplies
 * its initial bytes; conversion preserves bytes the original did not write.
 * It must not alias guest memory. No normalization of IPv6 auxiliary fields. */
uint8_t h2_network_socket_bind(h2_memory *,const h2_socket_creation_platform *,const h2_socket_option_platform *,const h2_socket_bind_platform *,uint32_t socket,uint32_t address,uint8_t workspace[28]); /* 000b4ed0 */
/* Host adapter for a stack-local engine address. */
uint8_t h2_network_socket_bind_bytes(h2_memory *,const h2_socket_creation_platform *,const h2_socket_option_platform *,const h2_socket_bind_platform *,uint32_t socket,const uint8_t address[20],uint8_t workspace[28]);
#endif
