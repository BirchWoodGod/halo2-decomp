#ifndef HALO2_NETWORK_OBSERVER_REBUILD_H
#define HALO2_NETWORK_OBSERVER_REBUILD_H
#include "halo2/network_observer_tick.h"
#include "halo2/network_connection_allocate.h"
#include "halo2/text_format.h"
typedef struct {
    const h2_observer_tick_context *tick;
    const h2_text_format_platform *format;
    /* Disjoint guest temporaries, also separate from tick context scratch. */
    uint32_t local12c,arguments16;
} h2_observer_rebuild_context;
/* 00078900: stack observer, ret4. */
void h2_network_observer_rebuild_connections(h2_memory *,const h2_observer_rebuild_context *,uint32_t observer);
#endif
