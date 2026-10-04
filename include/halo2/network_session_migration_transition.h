#ifndef HALO2_NETWORK_SESSION_MIGRATION_TRANSITION_H
#define HALO2_NETWORK_SESSION_MIGRATION_TRANSITION_H
#include "halo2/network_session_send.h"
#include "halo2/network_observer_tick.h"
/* 00061570: EAX session, stack byte flag, ret4, void. */
void h2_network_session_begin_migration_transition(h2_memory *,const h2_session_send_context *,const h2_observer_tick_context *,uint32_t session,uint8_t flag);
#endif
