#ifndef HALO2_NETWORK_SESSION_MIGRATION_UPDATE_H
#define HALO2_NETWORK_SESSION_MIGRATION_UPDATE_H
#include "halo2/network_session_control.h"
#include "halo2/network_observer_tick.h"
/* 00061ef0: stack session, ret4, void. Disjoint 200-byte payload scratch. */
void h2_network_session_tick_migration(h2_memory *,const h2_session_control_context *,const h2_observer_tick_context *,uint32_t session,uint32_t payload);
#endif
