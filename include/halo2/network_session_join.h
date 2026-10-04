#ifndef HALO2_NETWORK_SESSION_JOIN_H
#define HALO2_NETWORK_SESSION_JOIN_H
#include "halo2/network_session_join_retry.h"
#include "halo2/network_session_status.h"
/* 000617c0: EAX session, no stack arguments, void. Caller supplies disjoint
 * confirmation8, retry_payload0x1b8 and query4, separate from control scratch. */
void h2_network_session_tick_join(h2_memory *,const h2_network_query_platform *,
    const h2_session_control_context *,uint32_t session,uint32_t confirmation,
    uint32_t retry_payload,uint32_t query_scratch);
#endif
