#ifndef HALO2_NETWORK_OBSERVER_ROUTE_MODE_H
#define HALO2_NETWORK_OBSERVER_ROUTE_MODE_H
#include "halo2/memory.h"
/* 0007a4a0: EAX observer, void; writes gated global route mode. */
void h2_network_observer_update_route_mode(h2_memory *,uint32_t observer);
#endif
