#ifndef HALO2_NETWORK_CONNECTION_H
#define HALO2_NETWORK_CONNECTION_H
#include "halo2/network_messages.h"
#include "halo2/network_storage.h"
typedef struct {
    void *context;
    void (*closed)(void *,uint32_t function,uint32_t argument);
} h2_connection_callbacks;
/* local_scratch is 12 bytes, disjoint from live objects and packet scratch. */
void h2_network_connection_close(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    uint32_t connection,uint32_t reason,uint32_t local_scratch,uint32_t packet_scratch,uint8_t address_workspace[28]); /* 00088650 */
void h2_network_endpoint_close_connections(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    uint32_t endpoint,uint32_t local_scratch,uint32_t packet_scratch,uint8_t address_workspace[28]); /* 00092f10 */
void h2_network_connection_dispose(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    const h2_network_storage_operations *,uint32_t connection,uint32_t local_scratch,
    uint32_t packet_scratch,uint32_t storage_scratch,uint8_t address_workspace[28]); /* 000886e0 */
#endif
