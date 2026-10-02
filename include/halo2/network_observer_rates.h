#ifndef HALO2_NETWORK_OBSERVER_RATES_H
#define HALO2_NETWORK_OBSERVER_RATES_H
#include "halo2/memory.h"
float h2_network_observer_next_rate(h2_memory *,uint32_t observer,float current,uint8_t capped); /* 00078210, XMM3 input/XMM0 result, ret8 */
float h2_network_observer_select_rate(h2_memory *,uint32_t observer,uint32_t budget,uint8_t alternate,uint8_t capped); /* 00078090, XMM0 result, ret12 */
uint32_t h2_network_observer_rate_budget(h2_memory *,uint32_t observer,uint8_t alternate,float rate); /* 00078150, ret4 */
uint8_t h2_network_observer_rate_limited(h2_memory *,uint32_t observer,float rate,uint8_t configured,uint8_t baseline,uint8_t capped); /* 00078190, AL, ret12 */
#endif
