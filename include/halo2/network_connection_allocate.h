#ifndef HALO2_NETWORK_CONNECTION_ALLOCATE_H
#define HALO2_NETWORK_CONNECTION_ALLOCATE_H
#include "halo2/network_connection.h"
#include "halo2/network_slot_alloc.h"
/* Init88110: ESI connection, EDX index, stack flags/endpoint/writer/provider/config, ret20, AL.
 * Allocate82060: stack label(unused)/flags, ret8, DWORD index. */
uint8_t h2_network_connection_initialize(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,const h2_network_storage_operations *,uint32_t connection,uint32_t index,uint32_t flags,uint32_t endpoint,uint32_t writer,uint32_t provider,uint32_t config,uint32_t close12,uint32_t packet,uint32_t storage8,uint8_t workspace[28]);
uint32_t h2_network_connection_allocate(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,const h2_network_storage_operations *,uint32_t label,uint32_t flags,uint32_t close12,uint32_t packet,uint32_t storage8,uint8_t workspace[28]);
#endif
