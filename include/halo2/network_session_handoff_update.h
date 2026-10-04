#ifndef HALO2_NETWORK_SESSION_HANDOFF_UPDATE_H
#define HALO2_NETWORK_SESSION_HANDOFF_UPDATE_H
#include "halo2/network_session_control.h"
#include "halo2/network_session_candidate_rank.h"
/* DRAFT: original 00061ac0, stack session, ret4, void.
 * Caller provides disjoint 46-byte offer and 8-byte confirmation scratch.
 * Not integrated: preview uses a controlled CRT power boundary.
 * Production math provider and live session validation remain outstanding. */
void h2_network_session_tick_handoff(h2_memory *,const h2_session_control_context *,const h2_candidate_rank_math *,uint32_t session,uint32_t offer,uint32_t confirmation);
#endif
