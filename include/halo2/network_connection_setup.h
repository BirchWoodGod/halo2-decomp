#ifndef HALO2_NETWORK_CONNECTION_SETUP_H
#define HALO2_NETWORK_CONNECTION_SETUP_H
#include "halo2/network_state.h"
/* 00088d20: EAX connection; 00095cf0: ESI stream. Both return void. */
void h2_network_connection_reset_timers(h2_memory *, const h2_network_state_operations *, uint32_t connection);
void h2_network_stream_reset(h2_memory *, const h2_network_state_operations *, uint32_t stream);
#endif
