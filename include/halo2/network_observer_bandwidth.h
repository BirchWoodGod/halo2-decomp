#ifndef HALO2_NETWORK_OBSERVER_BANDWIDTH_H
#define HALO2_NETWORK_OBSERVER_BANDWIDTH_H
#include "halo2/network_state.h"
/* 000779f0, EDI observer. Requires default nearest-even floating rounding. */
void h2_network_observer_update_bandwidth(h2_memory *, const h2_network_state_operations *, uint32_t observer);
#endif
