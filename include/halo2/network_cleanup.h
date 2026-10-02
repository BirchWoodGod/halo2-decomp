#ifndef HALO2_NETWORK_CLEANUP_H
#define HALO2_NETWORK_CLEANUP_H
#include "halo2/network_observer.h"
typedef struct {
    void *context;
    void (*destroy_provider)(void *,uint32_t function,uint32_t object,uint32_t flags);
    void (*free_wrapper)(void *,uint32_t allocation); /* CRT thunk 00321379 */
} h2_network_cleanup_platform;
void h2_network_connections_dispose(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    const h2_network_registration_platform *,const h2_observer_events *,const h2_network_storage_operations *,
    const h2_network_cleanup_platform *,uint32_t local_scratch,uint32_t packet_scratch,uint32_t storage_scratch,uint8_t address_workspace[28]); /* 00081f80 */
#endif
