#ifndef HALO2_NETWORK_SESSION_REMOVAL_H
#define HALO2_NETWORK_SESSION_REMOVAL_H
#include "halo2/memory.h"
void h2_network_session_refresh_peer_flag(h2_memory *,uint32_t session); /* 0005a2e0: EDX session */
/* scratch4 models the reused stack argument and must be disjoint from live data. */
void h2_network_session_remove_player(h2_memory *,uint32_t session,uint32_t index,uint32_t scratch4); /* 00060200: ESI session, stack index */
/* Index must identify a live peer; membership counts/indices must be valid. */
void h2_network_session_remove_peer(h2_memory *,uint32_t session,uint32_t index,uint32_t scratch4); /* 0005fe20: EAX session, EBX index */
#endif
