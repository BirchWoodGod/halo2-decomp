#ifndef HALO2_NETWORK_GAME_ROUTES_H
#define HALO2_NETWORK_GAME_ROUTES_H
#include "halo2/network_game_overlap.h"
#include "halo2/network_game_route_queries.h"
#include "halo2/network_game_route_select.h"
/* 000565c0: stack table/requested/output, ret12. Output is two words.
 * Scratch is 24 disjoint guest bytes replacing original/nested stack locals. */
void h2_network_game_build_routes(h2_memory *,uint32_t table,uint32_t requested,uint32_t output,uint32_t scratch);
#endif
