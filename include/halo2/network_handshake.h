#ifndef HALO2_NETWORK_HANDSHAKE_H
#define HALO2_NETWORK_HANDSHAKE_H
#include "halo2/network_connection.h"
/* 000890b0 EAX connection, void. Disjoint scratch: message8, close12, packet0x1828. */
void h2_network_connection_update_handshake(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,uint32_t connection,uint32_t message8,uint32_t close12,uint32_t packet,uint8_t workspace[28]);
#endif
