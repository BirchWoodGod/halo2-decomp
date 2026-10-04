#ifndef HALO2_NETWORK_GAME_MEMBERS_H
#define HALO2_NETWORK_GAME_MEMBERS_H
#include "halo2/network_game_queries.h"
/* Scratch: disjoint four-byte guest cell replacing nested stack output. */
uint32_t h2_network_game_matching_members(h2_memory *,uint32_t scratch); /* 00054d20 EAX */
uint32_t h2_network_game_member_value(h2_memory *,uint32_t table,uint32_t index,uint32_t scratch); /* 00055960 ESI table, EBX index, EAX */
#endif
