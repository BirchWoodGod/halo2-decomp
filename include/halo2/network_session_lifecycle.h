#ifndef HALO2_NETWORK_SESSION_LIFECYCLE_H
#define HALO2_NETWORK_SESSION_LIFECYCLE_H
#include "halo2/network_messages.h"
/* SDK calls remain host integration boundaries. Return values are ignored. */
typedef struct {
    void *context;
    uint32_t (*session_release)(void *,uint32_t identity,uint32_t a,uint32_t b,uint32_t c,uint32_t flags);
    uint32_t (*key_release)(void *,uint32_t key);
} h2_session_registration_platform;
void h2_network_session_detach_peer(h2_memory *,uint32_t session,uint32_t index); /* 0005f970 */
void h2_network_session_release_registration(h2_memory *,const h2_session_registration_platform *,uint32_t session); /* 0005fb60 */
/* Scratch must be disjoint from live guest objects and from each other.
 * Update uses 16 bytes; begin uses 112 saved-state bytes plus 16 message bytes.
 * Packet scratch is 0x1828 bytes; address workspace follows the send API. */
void h2_network_session_update_join_abort(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,uint32_t session,uint32_t message_scratch,uint32_t packet_scratch,uint8_t workspace[28]); /* 000623e0 */
void h2_network_session_begin_join_abort(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,uint32_t session,uint32_t saved_state_scratch,uint32_t message_scratch,uint32_t packet_scratch,uint8_t workspace[28]); /* 00061180 */
#endif
