#ifndef HALO2_NETWORK_OBSERVER_ADMIT_H
#define HALO2_NETWORK_OBSERVER_ADMIT_H
#include "halo2/network_observer_tick.h"
#include "halo2/network_connection_allocate.h"
#include "halo2/text_format.h"
typedef struct {
    const h2_observer_tick_context *network;
    const h2_async_task_platform *async;
    const h2_text_format_platform *format;
    /* Disjoint scratch: identity36, label256, formatter arguments24. */
    uint32_t identity36,label256,arguments24;
} h2_observer_admit_context;
uint32_t h2_network_observer_admit(h2_memory *,const h2_observer_admit_context *,uint32_t observer,uint32_t consumer,uint32_t identity); /* 00076aa0 stack3 ret12 EAX */
#endif
