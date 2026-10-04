#ifndef HALO2_NETWORK_GAME_ROUTE_QUERIES_H
#define HALO2_NETWORK_GAME_ROUTE_QUERIES_H
#include "halo2/network_game_queries.h"
uint32_t h2_network_game_route_limit(h2_memory *); /* 00054cc0 EAX */
uint8_t h2_network_game_nonselected_id(h2_memory *,uint32_t scratch); /* 00054c70 AL */
uint32_t h2_network_game_selected_peer_mask(h2_memory *,uint32_t scratch); /* 00054ac0 EAX */
/* Scratch replaces nested stack output; must be disjoint four-byte guest cell. */
#endif
