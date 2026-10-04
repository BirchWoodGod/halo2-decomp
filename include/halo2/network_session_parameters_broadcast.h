#ifndef HALO2_NETWORK_SESSION_PARAMETERS_BROADCAST_H
#define HALO2_NETWORK_SESSION_PARAMETERS_BROADCAST_H
#include "halo2/network_session_send.h"
/* Preview 000627e0: ECX session, void. Initial comparisons pass; not integrated.
 * Full and delta scratch each provide 0x14d8 disjoint bytes. */
void h2_network_session_broadcast_parameters(h2_memory *,const h2_session_send_context *,uint32_t session,uint32_t full,uint32_t delta);
#endif
