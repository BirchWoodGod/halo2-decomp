#ifndef HALO2_NETWORK_SESSION_RESERVATION_EXPIRY_H
#define HALO2_NETWORK_SESSION_RESERVATION_EXPIRY_H
#include "halo2/network_state.h"
/* 00062de0, EAX session, void. */
void h2_network_session_expire_reservations(h2_memory *,const h2_network_state_operations *,uint32_t session);
#endif
