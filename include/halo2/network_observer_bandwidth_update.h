#ifndef HALO2_NETWORK_OBSERVER_BANDWIDTH_UPDATE_H
#define HALO2_NETWORK_OBSERVER_BANDWIDTH_UPDATE_H
#include "halo2/network_observer_cycle.h"
#include "halo2/network_observer_measurement.h"
/* 00079260: EAX observer, no stack arguments. */
void h2_network_observer_commit_bandwidth(h2_memory *,const h2_network_state_operations *,uint32_t observer);
#endif
