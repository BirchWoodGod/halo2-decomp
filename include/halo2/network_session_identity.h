#ifndef HALO2_NETWORK_SESSION_IDENTITY_H
#define HALO2_NETWORK_SESSION_IDENTITY_H
#include "halo2/network_state.h"
/* scratch6 is disjoint from session/input; models the original six-byte local. */
uint32_t h2_network_session_find_machine(h2_memory *,uint32_t session,uint32_t identity,uint32_t scratch6); /* 0005f6f0 */
uint32_t h2_network_session_find_player(h2_memory *,uint32_t session,uint32_t identity); /* 0005f890 */
uint8_t h2_network_session_queue_identity(h2_memory *,const h2_network_state_operations *,uint32_t session,uint32_t identity,uint32_t owner_identity,uint32_t value,uint32_t argument); /* 00062eb0 */
#endif
