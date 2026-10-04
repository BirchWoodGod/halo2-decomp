#ifndef HALO2_NETWORK_OBSERVER_BANDWIDTH_ALLOCATE_H
#define HALO2_NETWORK_OBSERVER_BANDWIDTH_ALLOCATE_H
#include "halo2/network_state.h"
#include "halo2/network_observer_metrics.h"
/* 00078e60: EAX slot index, stack observer, ret4. Default floating environment.
 * Like the original, invalid integer divisors are outside the normal domain. */
void h2_network_observer_allocate_bandwidth(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index);
#endif
