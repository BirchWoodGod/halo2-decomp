#ifndef HALO2_NETWORK_SESSION_MEMBERSHIP_H
#define HALO2_NETWORK_SESSION_MEMBERSHIP_H
#include "halo2/network_state.h"
void h2_network_session_attach_peer(h2_memory *,const h2_network_state_operations *,uint32_t session,uint32_t index,uint8_t active,uint32_t observer_index); /* 0005f900 */
void h2_network_session_add_peer(h2_memory *,const h2_network_state_operations *,uint32_t session,uint32_t index,uint32_t identity,uint8_t active,uint32_t observer_index,uint32_t extra_identity); /* 0005fbd0 */
#endif
