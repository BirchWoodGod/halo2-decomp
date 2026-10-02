#ifndef HALO2_DISCOVERY_H
#define HALO2_DISCOVERY_H
#include "halo2/network_messages.h"
#include "halo2/random.h"
#include "halo2/online_tasks.h"
#include "halo2/async_tasks.h"
void h2_discovery_store_reply(h2_memory *,const h2_network_state_operations *,uint32_t reply); /* 000b2fc0 */
void h2_message_handle_broadcast_reply(h2_memory *,const h2_network_state_operations *,uint32_t reply,uint32_t address); /* 000940b0 */
/* local_scratch is 32 bytes; preserve incoming address padding. Keep it
 * disjoint from live objects and the packet scratch workspace. */
void h2_discovery_update(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_message_codec_platform *,
    uint32_t local_scratch,uint32_t packet_scratch,uint8_t address_workspace[28]); /* 000b2ea0 */
uint8_t h2_discovery_start(h2_memory *,const h2_random_sources *,const h2_random_bytes_platform *,uint32_t cache,uint32_t count); /* 000b2e30 */
void h2_discovery_cancel_tasks(h2_memory *,const h2_online_task_platform *,const h2_async_task_platform *); /* 000b31b0 */
void h2_discovery_stop(h2_memory *,const h2_online_task_platform *,const h2_async_task_platform *,const h2_allocator *); /* 000b3670 */
#endif
