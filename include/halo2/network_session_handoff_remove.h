#ifndef HALO2_NETWORK_SESSION_HANDOFF_REMOVE_H
#define HALO2_NETWORK_SESSION_HANDOFF_REMOVE_H
#include "halo2/network_state.h"
/* 00061950: ESI session, ECX peer, no stack arguments, void. */
void h2_network_session_remove_handoff_candidate(h2_memory *,const h2_network_state_operations *,uint32_t session,uint32_t peer);
#endif
