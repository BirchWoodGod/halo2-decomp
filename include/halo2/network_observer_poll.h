#ifndef HALO2_NETWORK_OBSERVER_POLL_H
#define HALO2_NETWORK_OBSERVER_POLL_H
#include "halo2/network_state.h"
typedef struct {
    void *context;
    uint8_t (*query)(void *, uint32_t function, uint32_t object, uint32_t index);
} h2_observer_consumer_query;
/* 00077940: EAX observer, EBX index, AL result. Project-assigned name. */
uint8_t h2_network_observer_poll_consumers(h2_memory *,
    const h2_network_state_operations *, const h2_observer_consumer_query *,
    uint32_t observer, uint32_t index);
#endif
