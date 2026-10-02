#ifndef HALO2_NETWORK_ROUTE_INSERT_H
#define HALO2_NETWORK_ROUTE_INSERT_H
#include "halo2/network_connection.h"
/* 00092d10: ESI endpoint, stack connection index / sequence / address, ret12, AL. */
uint8_t h2_network_endpoint_insert_route(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,const h2_network_storage_operations *,uint32_t endpoint,uint32_t index,uint32_t sequence,uint32_t address,uint32_t local12,uint32_t packet,uint32_t storage_scratch,uint8_t workspace[28]);
#endif
