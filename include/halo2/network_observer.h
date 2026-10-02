#ifndef HALO2_NETWORK_OBSERVER_H
#define HALO2_NETWORK_OBSERVER_H
#include "halo2/network_connection.h"
#include "halo2/network_registration.h"
#include "halo2/async_tasks.h"
#include "halo2/network_resolution.h"
/* local_scratch is 16 disjoint bytes: 12 for close, four for address output. */
void h2_network_observer_detach(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    const h2_network_registration_platform *,uint32_t observer,uint32_t index,uint32_t mark,uint32_t reason,
    uint32_t local_scratch,uint32_t packet_scratch,uint8_t address_workspace[28]); /* 000784a0 */
/* Cleanup also needs eight disjoint bytes for storage-clear stack state. */
void h2_network_observer_release_slot(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    const h2_network_registration_platform *,const h2_network_storage_operations *,const h2_async_task_platform *,
    uint32_t observer,uint32_t index,uint32_t local_scratch,uint32_t packet_scratch,uint32_t storage_scratch,uint8_t address_workspace[28]); /* 00076ef0 */
void h2_network_observer_dispose(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    const h2_network_registration_platform *,const h2_network_storage_operations *,const h2_async_task_platform *,
    uint32_t observer,uint32_t local_scratch,uint32_t packet_scratch,uint32_t storage_scratch,uint8_t address_workspace[28]); /* 00075a40 */
typedef struct {
    void *context;
    void (*state_one)(void *,uint32_t function,uint32_t object,uint32_t index);
    void (*connection)(void *,uint32_t function,uint32_t object,uint32_t index,uint32_t identifier,uint32_t connected);
} h2_observer_events;
void h2_network_observer_set_state(h2_memory *,const h2_network_state_operations *,const h2_observer_events *,uint32_t observer,uint32_t index,uint32_t state); /* 00077330 */
void h2_network_observer_update_slot(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    const h2_network_registration_platform *,const h2_observer_events *,uint32_t observer,uint32_t index,
    uint32_t local_scratch,uint32_t packet_scratch,uint8_t address_workspace[28]); /* 00076ff0 */
void h2_network_observer_close_connections(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,
    const h2_network_registration_platform *,const h2_observer_events *,const h2_network_storage_operations *,
    uint32_t observer,uint32_t local_scratch,uint32_t packet_scratch,uint32_t storage_scratch,uint8_t address_workspace[28]); /* 00078880 */
/* local: 80 disjoint bytes (44 incoming locals, reused argument4, resolution28,
 * padding4). Reliable scratch is 0x10037 bytes; packet scratch is 0x1828 bytes. */
void h2_network_observer_send(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_network_resolution_platform *,const h2_network_storage_queue_operations *,uint32_t observer,uint32_t index,uint32_t consumer,uint8_t unreliable,uint32_t type,uint32_t size,uint32_t payload,uint32_t local,uint32_t reliable_scratch,uint32_t packet_scratch,uint8_t address_workspace[28]); /* 00075e80 */
#endif
