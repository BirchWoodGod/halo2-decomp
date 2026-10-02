#ifndef HALO2_NETWORK_RESOLUTION_H
#define HALO2_NETWORK_RESOLUTION_H
#include "halo2/network_address.h"
/* SDK entry points: resolve=003cd0ec, prepare=003cd34f.
 * A zero return status is success; no completed network connection is implied. */
typedef struct {
    void *context;
    uint32_t (*resolve)(void *,uint32_t peer,uint32_t key,uint32_t output_ipv4);
    uint32_t (*prepare)(void *,uint32_t ipv4);
} h2_network_resolution_platform;
uint8_t h2_network_address_valid(h2_memory *,uint32_t address); /* 0007af40 */
/* Four guest scratch bytes model the reused peer argument or local address.
 * They must be disjoint from caller data and outputs. */
uint8_t h2_network_address_resolve_key(h2_memory *,const h2_network_resolution_platform *,uint32_t index,uint32_t kind,uint32_t output,uint32_t peer,uint16_t port,uint32_t scratch); /* 0007adf0 */
uint8_t h2_network_address_resolve(h2_memory *,const h2_network_resolution_platform *,uint32_t index,uint32_t output,uint32_t peer,uint32_t kind,uint16_t port,uint32_t scratch); /* 0007ab10 */
uint8_t h2_network_address_prepare(h2_memory *,const h2_network_resolution_platform *,uint32_t address,uint32_t scratch); /* 0007acc0 */
/* 28 disjoint guest scratch bytes: incoming address20, reused peer4, IPv4 local4. */
uint8_t h2_network_observer_resolve_address(h2_memory *,const h2_network_resolution_platform *,uint32_t observer,uint32_t consumer,uint32_t peer,uint32_t address_out,uint32_t index_out,uint32_t identity_out,uint32_t key_out,uint32_t scratch); /* 000783d0 */
#endif
