#ifndef HALO2_NETWORK_SESSION_EVICTION_H
#define HALO2_NETWORK_SESSION_EVICTION_H
#include "halo2/network_session_send.h"
/* 0005fda0: ESI session, EAX peer, void. Disjoint message8/removal4. */
void h2_network_session_evict_peer(h2_memory *,const h2_session_send_context *,uint32_t session,uint32_t peer,uint32_t message8,uint32_t removal4);
#endif
