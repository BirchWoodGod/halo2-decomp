#ifndef HALO2_NETWORK_OBSERVER_TICK_H
#define HALO2_NETWORK_OBSERVER_TICK_H
#include "halo2/network_observer_selection.h"
#include "halo2/network_connection_open.h"
typedef struct {
    const h2_network_state_operations *clock;
    const h2_socket_send_platform *send;
    const h2_message_codec_platform *codec;
    const h2_connection_callbacks *connections;
    const h2_network_registration_platform *registration;
    const h2_observer_events *events;
    const h2_network_storage_operations *storage;
    const h2_network_query_platform *query;
    const h2_network_resolution_platform *resolution;
    void *context;
    uint8_t (*request)(void *,uint32_t function,uint32_t object,uint32_t index,uint32_t reconnect);
    /* Disjoint guest scratch: 4,16,28,8,8,0x1828 bytes respectively. */
    uint32_t query4,detach16,resolution28,message8,storage8,packet;
    uint8_t *workspace28;
} h2_observer_tick_context;
void h2_network_observer_tick(h2_memory *,const h2_observer_tick_context *,uint32_t observer,uint32_t index); /* 000776a0 ECX observer, stack index, ret4 */
void h2_network_observer_request_connection(h2_memory *,const h2_observer_tick_context *,uint32_t observer,uint32_t index); /* 00076a40 ECX observer, EAX index */
#endif
