#ifndef HALO2_NETWORK_OBSERVER_METRICS_H
#define HALO2_NETWORK_OBSERVER_METRICS_H
#include "halo2/network_observer_rates.h"
/* 00078a10: ECX index, EDX observer, four stack outputs, ret16, AL.
 * Output aliases preserve original ordered stores and subsequent reads. */
uint8_t h2_network_observer_get_metrics(h2_memory *,uint32_t observer,uint32_t index,uint32_t metric4,uint32_t rate4,uint32_t sample4,uint32_t ratio4);
/* 00079600: ECX observer, EAX index, XMM5 rate, stack budget/burst, ret8. */
void h2_network_observer_apply_rate(h2_memory *,uint32_t observer,uint32_t index,float rate,uint32_t budget,uint32_t burst);
#endif
