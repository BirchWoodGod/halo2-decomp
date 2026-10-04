#ifndef HALO2_NETWORK_CONNECTION_ITERATION_H
#define HALO2_NETWORK_CONNECTION_ITERATION_H
#include "halo2/network_state.h"
/* Iterator words: required flags, cursor, combined index, flags, object.
 * 000891e0: EBX connection, stack iterator, ret4; only AL is the result. */
uint8_t h2_network_connection_next_component(h2_memory *,uint32_t connection,uint32_t iterator);
/* 00088d70: ESI connection, EAX timestamp slot; void. */
void h2_network_connection_stamp(h2_memory *,const h2_network_state_operations *,uint32_t connection,uint32_t slot);
#endif
