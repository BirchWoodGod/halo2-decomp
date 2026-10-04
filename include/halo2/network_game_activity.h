#ifndef HALO2_NETWORK_GAME_ACTIVITY_H
#define HALO2_NETWORK_GAME_ACTIVITY_H
#include "halo2/network_game_member_routes.h"
#include "halo2/network_game_members.h"
/* 00054890: stack peer index, ret4, AL. Scratch is 28 disjoint guest bytes
 * replacing query/routing locals and the predicate's two-word route result. */
uint8_t h2_network_game_peer_active(h2_memory *,uint32_t peer,uint32_t scratch);
#endif
