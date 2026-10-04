#ifndef HALO2_NETWORK_GAME_MEMBER_ROUTES_H
#define HALO2_NETWORK_GAME_MEMBER_ROUTES_H
#include "halo2/network_game_routes.h"
#include "halo2/network_game_peer_mask.h"
/* 00056590: EAX member mask, EDI table, ESI two-word output; void.
 * Scratch: 24 disjoint guest bytes for nested recovered routines. */
void h2_network_game_member_routes(h2_memory *,uint32_t members,uint32_t table,uint32_t output,uint32_t scratch);
#endif
