#ifndef HALO2_NETWORK_OBSERVER_PROBE_H
#define HALO2_NETWORK_OBSERVER_PROBE_H
#include "halo2/network_state.h"
#include "halo2/network_observer_metrics.h"
void h2_network_observer_reset_probe(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index); /* 00079d90 ECX,EAX */
void h2_network_observer_restore_probe(h2_memory *,uint32_t observer,uint32_t index); /* 0007a110 ECX,EAX */
float h2_network_observer_probe_priority(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index); /* 0007a2a0 ESI,EAX; XMM0 result */
#endif
