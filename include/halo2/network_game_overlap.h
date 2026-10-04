#ifndef HALO2_NETWORK_GAME_OVERLAP_H
#define HALO2_NETWORK_GAME_OVERLAP_H
#include "halo2/network_game_session.h"
uint32_t h2_network_game_session_kind(h2_memory *); /* 00054f20 EAX */
/* 00053c70 no original arguments, EAX mask. Scratch is eight disjoint guest
 * bytes replacing the two original stack-local session pointers. Requires a
 * valid B descriptor when both session getters succeed, as in the original. */
uint32_t h2_network_game_session_overlap(h2_memory *,uint32_t scratch);
#endif
