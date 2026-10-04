#ifndef HALO2_NETWORK_SESSION_DISCONNECT_H
#define HALO2_NETWORK_SESSION_DISCONNECT_H
#include "halo2/network_session_control.h"
#include "halo2/network_observer_admission.h"
/* 00062ab0: ESI session, no stack arguments, void. Valid session states 0..10.
 * Caller supplies disjoint 12-byte close and 0x118-byte migration scratch. */
void h2_network_session_handle_disconnect(h2_memory *,const h2_session_control_context *,const h2_connection_callbacks *,uint32_t session,uint32_t close_scratch,uint32_t migration_scratch);
#endif
