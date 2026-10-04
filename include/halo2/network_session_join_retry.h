#ifndef HALO2_NETWORK_SESSION_JOIN_RETRY_H
#define HALO2_NETWORK_SESSION_JOIN_RETRY_H
#include "halo2/network_observer_query.h"
/* 00062300: EBX session, no stack arguments, void. Disjoint scratch:
 * payload0x1b8, address-query4, packet0x1828 and host address workspace28. */
void h2_network_session_resend_join(h2_memory *,const h2_network_query_platform *,
    const h2_network_state_operations *,const h2_socket_send_platform *,
    const h2_message_codec_platform *,uint32_t session,uint32_t payload,
    uint32_t query_scratch,uint32_t packet,uint8_t workspace[28]);
#endif
