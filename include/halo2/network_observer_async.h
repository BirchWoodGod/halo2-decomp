#ifndef HALO2_NETWORK_OBSERVER_ASYNC_H
#define HALO2_NETWORK_OBSERVER_ASYNC_H
#include "halo2/async_task_create.h"
/* records60 is a disjoint per-invocation guest temporary. */
void h2_network_observer_async(h2_memory *, const h2_async_task_create_platform *,
    uint32_t observer, uint32_t index, uint32_t records60); /* 00077480 */
#endif
