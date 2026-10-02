#ifndef HALO2_NETWORK_ENDPOINT_H
#define HALO2_NETWORK_ENDPOINT_H
#include "halo2/memory.h"
#include "halo2/network_state.h"
void h2_network_statistics_advance(h2_memory *, const h2_network_state_operations *, uint32_t statistics); /* 000928e0 */
void h2_network_samples_reset(h2_memory *, const h2_network_state_operations *, uint32_t samples); /* 000929d0 */
void h2_network_samples_add(h2_memory *, const h2_network_state_operations *, uint32_t samples, uint32_t value); /* 00092a30 */
/* Socket creation/configuration remains external. close_all can call recovered
 * h2_network_endpoint_close with the host platform context. */
typedef struct {
    void *context;
    uint8_t (*open)(void *,uint32_t type,uint32_t port,uint32_t special,uint32_t output);
    void (*close_all)(void *,uint32_t endpoint);
} h2_endpoint_operations;
void h2_network_statistics_initialize(h2_memory *,uint32_t statistics,int32_t interval); /* 00092870 */
uint8_t h2_network_endpoint_open(h2_memory *,const h2_endpoint_operations *,uint32_t endpoint); /* 00092bf0 */
uint8_t h2_network_endpoint_initialize(h2_memory *,const h2_endpoint_operations *,uint32_t endpoint); /* 00092a90 */
#endif
