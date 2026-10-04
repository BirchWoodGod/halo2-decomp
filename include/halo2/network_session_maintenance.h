#ifndef HALO2_NETWORK_SESSION_MAINTENANCE_H
#define HALO2_NETWORK_SESSION_MAINTENANCE_H
#include "halo2/network_observer_tick.h"
/* 00062240, EDI session, no stack arguments, void. */
void h2_network_session_maintain_connections(h2_memory *,const h2_observer_tick_context *,uint32_t session);
#endif
