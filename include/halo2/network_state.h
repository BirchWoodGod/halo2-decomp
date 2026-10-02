#ifndef HALO2_NETWORK_STATE_H
#define HALO2_NETWORK_STATE_H
#include "halo2/memory.h"
/* Names describe recovered setup behavior; original type names are unknown. */
typedef struct {
    void *context;
    uint32_t (*ticks)(void *);
    uint8_t (*provider_initialize)(void *,uint32_t function,uint32_t provider_slot);
} h2_network_state_operations;
uint8_t h2_network_state_initialize(h2_memory *,const h2_network_state_operations *,uint32_t state,uint32_t dependency_a,uint32_t dependency_b,uint32_t dependency_c,uint32_t config); /* 00075970 */
uint8_t h2_network_global_state_initialize(h2_memory *,uint32_t dependency); /* 00063d50 */
void h2_network_provider_initialize(h2_memory *,const h2_network_state_operations *); /* 000662f0 */
uint8_t h2_network_auxiliary_initialize(h2_memory *, uint32_t dependency_a,
    uint32_t dependency_b); /* 0007f020 */
void h2_network_tracking_reset(h2_memory *); /* 0008e210 */
#endif
