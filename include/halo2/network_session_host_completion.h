#ifndef HALO2_NETWORK_SESSION_HOST_COMPLETION_H
#define HALO2_NETWORK_SESSION_HOST_COMPLETION_H
#include "halo2/network_session_control.h"
/* Draft 00061e00: EAX session, no stack arguments, void.
 * Disjoint scratch: eviction8, removal4, membership full/delta0x489c each,
 * parameters full/delta0x14d8 each, plus the control/send contexts' scratch. */
void h2_network_session_complete_host(h2_memory *,const h2_session_control_context *,uint32_t session,uint32_t eviction,uint32_t removal,uint32_t membership_full,uint32_t membership_delta,uint32_t parameters_full,uint32_t parameters_delta);
#endif
