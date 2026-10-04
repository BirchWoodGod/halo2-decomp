#ifndef HALO2_NETWORK_SESSION_MIGRATION_START_H
#define HALO2_NETWORK_SESSION_MIGRATION_START_H
#include "halo2/network_state.h"
/* 000616e0: stack session, ret 4, void. Scratch is 0x118 bytes,
 * disjoint from session and globals, replacing the original stack state. */
void h2_network_session_begin_migration(h2_memory *,const h2_network_state_operations *,uint32_t session,uint32_t scratch);
#endif
