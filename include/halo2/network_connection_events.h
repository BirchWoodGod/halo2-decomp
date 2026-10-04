#ifndef HALO2_NETWORK_CONNECTION_EVENTS_H
#define HALO2_NETWORK_CONNECTION_EVENTS_H
#include "halo2/network_connection_iteration.h"
#include "halo2/network_stream_events.h"
typedef struct {
    void *context;
    /* Original thiscall targets; argument_count is 1, 2 or 3. Boolean
     * argument words retain the original frame's unspecified upper bytes. */
    void (*invoke)(void *,uint32_t function,uint32_t object,uint32_t argument_count,
        uint32_t argument1,uint32_t argument2,uint32_t argument3);
} h2_connection_event_callbacks;
/* 00088db0: ESI connection, void. Scratch is 76 disjoint guest bytes:
 * 72 bytes mirroring incoming stack-local state plus a nested poll word.
 * Floating conversion uses the default nearest-even rounding mode. */
void h2_network_connection_dispatch_events(h2_memory *,const h2_network_state_operations *,
    const h2_connection_event_callbacks *,uint32_t connection,uint32_t scratch76);
#endif
