#ifndef HALO2_NETWORK_CONNECTION_OPEN_H
#define HALO2_NETWORK_CONNECTION_OPEN_H
#include "halo2/network_route_insert.h"
/* 00088220: EAX address, stack connection/active byte, ret8, void.
 * All scratch buffers must be disjoint from live objects and each other. */
void h2_network_connection_open(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,const h2_network_storage_operations *,uint32_t connection,uint32_t address,uint8_t active,uint32_t message8,uint32_t close12,uint32_t storage8,uint32_t packet,uint8_t workspace[28]);
#endif
