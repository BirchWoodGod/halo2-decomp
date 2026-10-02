#ifndef HALO2_NETWORK_OBSERVER_SELECTION_H
#define HALO2_NETWORK_OBSERVER_SELECTION_H
#include "halo2/network_observer_query.h"
/* All scratch is disjoint: query4, detach16, resolution28, packet0x1828. */
uint8_t h2_network_observer_select_address(h2_memory *,const h2_network_query_platform *,const h2_network_resolution_platform *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,const h2_network_registration_platform *,uint32_t observer,uint32_t index,uint32_t query4,uint32_t detach16,uint32_t resolution28,uint32_t packet,uint8_t workspace[28]); /* 00078330: EAX index, stack observer, ret4 */
#endif
