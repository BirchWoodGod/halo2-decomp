#ifndef HALO2_NETWORK_SESSION_SNAPSHOT_RESET_H
#define HALO2_NETWORK_SESSION_SNAPSHOT_RESET_H
#include "halo2/memory.h"
/* 00060fa0: EDX session, stack byte refresh, ret4, void. */
void h2_network_session_reset_snapshots(h2_memory *,uint32_t session,uint8_t refresh);
#endif
