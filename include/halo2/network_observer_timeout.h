#ifndef HALO2_NETWORK_OBSERVER_TIMEOUT_H
#define HALO2_NETWORK_OBSERVER_TIMEOUT_H
#include "halo2/network_observer_tick.h"
/* 000773a0: EAX slot index, stack observer, ret4. */
void h2_network_observer_check_timeout(h2_memory *,const h2_observer_tick_context *,uint32_t observer,uint32_t index);
#endif
