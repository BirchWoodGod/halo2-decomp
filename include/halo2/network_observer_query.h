#ifndef HALO2_NETWORK_OBSERVER_QUERY_H
#define HALO2_NETWORK_OBSERVER_QUERY_H
#include "halo2/network_observer.h"
typedef struct {
    void *context;
    uint32_t (*query)(void *,uint32_t ipv4); /* SDK 003cd35a */
} h2_network_query_platform;
/* scratch4 models the reused address local, disjoint from live objects. */
uint32_t h2_network_address_query(h2_memory *,const h2_network_query_platform *,uint32_t address,uint32_t scratch4); /* 0007acf0 */
uint32_t h2_network_observer_query(h2_memory *,const h2_network_query_platform *,uint32_t observer,uint32_t index,uint32_t scratch4); /* 00078580 */
/* local16/packet scratch follow detach's contract; query4 is disjoint from both. */
void h2_network_observer_refresh_address(h2_memory *,const h2_network_query_platform *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,const h2_network_registration_platform *,const h2_observer_events *,uint32_t observer,uint32_t index,uint32_t query4,uint32_t local16,uint32_t packet,uint8_t workspace[28]); /* 00076f50 */
#endif
