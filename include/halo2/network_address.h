#ifndef HALO2_NETWORK_ADDRESS_H
#define HALO2_NETWORK_ADDRESS_H
#include "halo2/network_options.h"
uint8_t h2_network_address_to_sockaddr(h2_memory *,uint32_t address,uint32_t output,uint32_t length); /* 000b5470 */
uint8_t h2_network_address_from_sockaddr(h2_memory *,uint32_t input,uint32_t length,uint32_t address); /* 000b5560 */
typedef struct {
    void *context;
    uint32_t (*create)(void *,uint32_t family,uint32_t type,uint32_t protocol);
    void (*last_error)(void *);
} h2_socket_creation_platform;
uint8_t h2_network_socket_ensure_handle(h2_memory *,const h2_socket_creation_platform *,const h2_socket_option_platform *,uint32_t socket,uint32_t address); /* 000b53e0 */
/* Host adapter for a stack-local address; not an additional recovered routine. */
uint8_t h2_network_socket_ensure_handle_for_width(h2_memory *,const h2_socket_creation_platform *,const h2_socket_option_platform *,uint32_t socket,uint32_t width);
uint8_t h2_network_address_registered_ipv4(h2_memory *,uint32_t address,uint32_t output); /* 0007aec0 */
#endif
