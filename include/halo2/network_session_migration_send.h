#ifndef HALO2_NETWORK_SESSION_MIGRATION_SEND_H
#define HALO2_NETWORK_SESSION_MIGRATION_SEND_H
#include "halo2/network_session_send.h"
/* 00062550: ESI session, no stack arguments, void.
 * Uses message8 and nested disjoint scratch from the send context. */
void h2_network_session_send_migration_requests(h2_memory *,const h2_session_send_context *,uint32_t session);
#endif
