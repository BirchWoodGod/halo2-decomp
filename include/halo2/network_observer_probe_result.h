#ifndef HALO2_NETWORK_OBSERVER_PROBE_RESULT_H
#define HALO2_NETWORK_OBSERVER_PROBE_RESULT_H
#include "halo2/network_observer_reduce.h"
/* Both rates: ECX observer, EAX index, EAX result; counters at entry+4a8/4a4. */
uint32_t h2_network_observer_measure_rate_a(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index); /* 00079560 */
uint32_t h2_network_observer_measure_rate_b(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index); /* 000795b0 */
void h2_network_observer_probe_failure(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index); /* 0007a160 ECX,EDI */
uint32_t h2_network_observer_probe_result(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index); /* 0007a1c0 EBX,stack index,ret4 */
#endif
