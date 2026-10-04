#ifndef HALO2_NETWORK_OBSERVER_PROBE_UPDATE_H
#define HALO2_NETWORK_OBSERVER_PROBE_UPDATE_H
#include "halo2/network_observer_probe_start.h"
/* 0007a330: EAX observer, stack index, ret4. Scratch is one disjoint guest
 * byte replacing the original stack-local exhausted flag. */
void h2_network_observer_update_probe(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index,uint32_t scratch);
#endif
