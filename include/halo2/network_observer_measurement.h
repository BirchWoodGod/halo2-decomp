#ifndef HALO2_NETWORK_OBSERVER_MEASUREMENT_H
#define HALO2_NETWORK_OBSERVER_MEASUREMENT_H
#include "halo2/network_state.h"
/* 00077f90: ESI observer, ECX sample, EAX reference, stack comparison; ret4. */
void h2_network_observer_record_measurement(h2_memory *, const h2_network_state_operations *,
    uint32_t observer, uint32_t sample, uint32_t reference, uint32_t comparison);
#endif
