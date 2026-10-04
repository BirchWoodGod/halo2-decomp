#ifndef HALO2_NETWORK_SESSION_STATUS_H
#define HALO2_NETWORK_SESSION_STATUS_H
#include "halo2/network_session_control.h"
/* Uses the control context's first28 control_message bytes for original locals,
 * plus its message-send context's disjoint scratch. Valid selected peer required. */
void h2_network_session_send_status_request(h2_memory *,const h2_session_control_context *,uint32_t session); /* 00062990 ESI */
void h2_network_session_begin_connected(h2_memory *,const h2_session_control_context *,uint32_t session); /* 000612c0 EAX */
#endif
