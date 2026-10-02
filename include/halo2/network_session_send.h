#ifndef HALO2_NETWORK_SESSION_SEND_H
#define HALO2_NETWORK_SESSION_SEND_H
#include "halo2/network_observer.h"
/* Host dependencies and disjoint scratch shared by sequential sends.
 * message: 8 bytes; local: 80 bytes; reliable: 0x10037 bytes;
 * packet: 0x1828 bytes; address_workspace: 28 host bytes.
 * These buffers must not overlap the session, payload, or other live objects. */
typedef struct {
    const h2_network_state_operations *clock;
    const h2_socket_send_platform *send;
    const h2_message_codec_platform *codec;
    const h2_network_resolution_platform *resolution;
    const h2_network_storage_queue_operations *queue;
    uint32_t message,local,reliable,packet;
    uint8_t *address_workspace;
} h2_session_send_context;
void h2_network_session_send_peer(h2_memory *,const h2_session_send_context *,uint32_t session,uint32_t peer,uint32_t mode,uint32_t type,uint32_t size,uint32_t payload); /* 00062d20 */
void h2_network_session_broadcast(h2_memory *,const h2_session_send_context *,uint32_t session,uint32_t mode,uint32_t type,uint32_t size,uint32_t payload); /* 00062da0 */
void h2_network_session_update_leave(h2_memory *,const h2_session_send_context *,uint32_t session); /* 00062480 */
void h2_network_session_begin_leave(h2_memory *,const h2_session_send_context *,uint32_t session); /* 00061330 */
void h2_network_session_begin_disband(h2_memory *,const h2_session_send_context *,uint32_t session); /* 00061450 */
#endif
