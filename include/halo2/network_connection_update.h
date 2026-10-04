#ifndef HALO2_NETWORK_CONNECTION_UPDATE_H
#define HALO2_NETWORK_CONNECTION_UPDATE_H
#include "halo2/network_connection_build.h"
#include "halo2/network_connection_events.h"
#include "halo2/network_handshake.h"
typedef struct {
    void *context;
    uint32_t (*invoke)(void *,uint32_t function,uint32_t object,uint32_t count,
        const uint32_t *arguments);
} h2_connection_update_callbacks;
typedef struct {
    const h2_network_state_operations *clock;
    const h2_socket_send_platform *send;
    const h2_message_codec_platform *codec;
    const h2_connection_callbacks *close;
    const h2_stream_reserve_callbacks *reserve;
    const h2_connection_build_callbacks *build;
    const h2_connection_event_callbacks *events;
    const h2_connection_update_callbacks *update;
} h2_connection_update_context;
/* 000883c0: EAX connection, no stack arguments, void.
 * Scratch0x4070 replaces 0x864 original local bytes plus disjoint callee locals.
 * Incoming unspecified local bytes are preserved. Original buffer/component
 * validity requirements apply; observer payload limits must fit these buffers. */
void h2_network_connection_update(h2_memory *,const h2_connection_update_context *,
    uint32_t connection,uint32_t scratch,uint8_t address_workspace[28]);
/* 00093090: stack endpoint, ret4, void. Same scratch contract; table count and
 * global connection pool reload after callbacks, selected connection retained. */
void h2_network_endpoint_update(h2_memory *,const h2_connection_update_context *,
    uint32_t endpoint,uint32_t scratch,uint8_t address_workspace[28]);
#endif
