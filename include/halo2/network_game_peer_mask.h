#ifndef HALO2_NETWORK_GAME_PEER_MASK_H
#define HALO2_NETWORK_GAME_PEER_MASK_H
#include "halo2/network_game_queries.h"
/* 00056990: EBX member mask, EAX result. Disjoint four-byte guest scratch
 * replaces nested session-selector stack output. */
uint32_t h2_network_game_peer_mask(h2_memory *,uint32_t members,uint32_t scratch);
#endif
