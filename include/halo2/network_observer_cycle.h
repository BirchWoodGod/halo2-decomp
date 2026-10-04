#ifndef HALO2_NETWORK_OBSERVER_CYCLE_H
#define HALO2_NETWORK_OBSERVER_CYCLE_H
#include "halo2/network_observer_probe_result.h"
/* 00079480: stack observer, ret4; captures first timestamp, then measures and
 * resets active entries before storing that timestamp. */
void h2_network_observer_finish_cycle(h2_memory *,const h2_network_state_operations *,uint32_t observer);
#endif
