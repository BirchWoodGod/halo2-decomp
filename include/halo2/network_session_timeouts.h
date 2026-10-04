#ifndef HALO2_NETWORK_SESSION_TIMEOUTS_H
#define HALO2_NETWORK_SESSION_TIMEOUTS_H
#include "halo2/network_session_control.h"
/* Both take EAX session, no stack arguments, void. Scratch/platform contracts
 * are inherited from the control context and its message context. */
void h2_network_session_tick_join_abort(h2_memory *,const h2_session_control_context *,uint32_t session); /* 000618d0 */
void h2_network_session_tick_leave(h2_memory *,const h2_session_control_context *,uint32_t session); /* 00061910 */
#endif
