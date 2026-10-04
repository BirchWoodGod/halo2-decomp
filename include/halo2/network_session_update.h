#ifndef HALO2_NETWORK_SESSION_UPDATE_H
#define HALO2_NETWORK_SESSION_UPDATE_H
#include "halo2/network_session_control.h"
#include "halo2/network_observer_tick.h"
#include "halo2/network_session_candidate_rank.h"
/* Draft 0005a090: EAX session, no stack arguments, void.
 * Not integrated or differentially validated. Handoff math fidelity unresolved.
 * Scratch regions are disjoint from each other, contexts and live guest objects;
 * sizes: confirmation8, retry0x1b8, query4, close12, migration0x118,
 * offer46, handoff_confirmation8, migration_payload200, eviction8, removal4,
 * membership_full/delta0x489c, parameters_full/delta0x14d8. */
typedef struct {
    uint32_t confirmation,retry,query,close,migration;
    uint32_t offer,handoff_confirmation,migration_payload,eviction,removal;
    uint32_t membership_full,membership_delta,parameters_full,parameters_delta;
} h2_session_update_scratch;
void h2_network_session_update(h2_memory *,const h2_session_control_context *,
    const h2_observer_tick_context *,const h2_candidate_rank_math *,uint32_t session,
    const h2_session_update_scratch *);
#endif
