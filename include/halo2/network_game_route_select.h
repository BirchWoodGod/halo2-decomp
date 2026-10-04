#ifndef HALO2_NETWORK_GAME_ROUTE_SELECT_H
#define HALO2_NETWORK_GAME_ROUTE_SELECT_H
#include "halo2/memory.h"
/* 00056790: EBX remaining-count pointer, EDX pending-mask pointer;
 * stack allowed/selected-word pointer/reserve-byte/local-ID/deferred-byte pointer,
 * ret20. Guest outputs may alias; ordered reads/stores preserve that behavior. */
void h2_network_game_select_routes(h2_memory *,uint32_t remaining,uint32_t pending,uint32_t allowed,uint32_t selected,uint8_t reserve,uint32_t local,uint32_t deferred);
#endif
