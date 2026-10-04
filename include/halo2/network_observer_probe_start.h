#ifndef HALO2_NETWORK_OBSERVER_PROBE_START_H
#define HALO2_NETWORK_OBSERVER_PROBE_START_H
#include "halo2/network_observer_probe_result.h"
/* 00079de0: EDI observer, stack index/exhausted-byte output, ret8, AL.
 * Default floating environment; valid integer divisors required. */
uint8_t h2_network_observer_start_probe(h2_memory *,const h2_network_state_operations *,uint32_t observer,uint32_t index,uint32_t exhausted);
#endif
