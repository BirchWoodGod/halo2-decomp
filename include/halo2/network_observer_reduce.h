#ifndef HALO2_NETWORK_OBSERVER_REDUCE_H
#define HALO2_NETWORK_OBSERVER_REDUCE_H
#include "halo2/network_observer_probe.h"
void h2_network_observer_reduce_peer(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index); /* 00079a10 EAX index,stack observer,ret4 */
void h2_network_observer_reduce_bandwidth(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index,uint8_t propagate); /* 00079c00 ECX observer,stack index/flag,ret8 */
#endif
