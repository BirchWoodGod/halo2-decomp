#ifndef HALO2_NETWORK_CONNECTION_ACCEPT_H
#define HALO2_NETWORK_CONNECTION_ACCEPT_H
#include "halo2/network_connection.h"
#include "halo2/network_storage.h"
typedef struct {
    const h2_network_state_operations *clock;
    const h2_socket_send_platform *send;
    const h2_message_codec_platform *codec;
    const h2_network_storage_queue_operations *queue;
    uint32_t message8,storage_scratch,packet;
    uint8_t *workspace28;
} h2_connection_accept_context;
void h2_network_connection_send_accept(h2_memory *,const h2_connection_accept_context *,uint32_t connection,uint8_t reliable); /* 00089180 EAX,stack flag,ret4 */
void h2_network_connection_accept(h2_memory *,const h2_connection_accept_context *,uint32_t connection,uint32_t remote_id); /* 00088360 ESI,stack id,ret4 */
#endif
