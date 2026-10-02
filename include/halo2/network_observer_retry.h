#ifndef HALO2_NETWORK_OBSERVER_RETRY_H
#define HALO2_NETWORK_OBSERVER_RETRY_H
#include "halo2/network_connection.h"
uint32_t h2_network_elapsed(h2_memory *,const h2_network_state_operations *,uint32_t previous); /* 00075890 */
uint32_t h2_network_connection_send_capacity(h2_memory *,uint32_t connection); /* 00089070 */
uint8_t h2_network_observer_retry_allowed(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,uint32_t observer,uint32_t index,uint32_t reason,uint32_t local12,uint32_t packet,uint8_t workspace[28]); /* 00077580 */
#endif
