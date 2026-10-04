#ifndef HALO2_NETWORK_GAME_QUERIES_H
#define HALO2_NETWORK_GAME_QUERIES_H
#include "halo2/network_game_session.h"
/* Scratch is a disjoint four-byte guest cell replacing stack-local output.
 * First four original routines take no arguments; flags/flag2 use EBX index. */
uint32_t h2_network_game_description(h2_memory *,uint32_t scratch); /* 00053de0 EAX */
uint32_t h2_network_game_selected_id(h2_memory *,uint32_t scratch); /* 00054a20 EAX */
uint32_t h2_network_game_member_mask(h2_memory *,uint32_t scratch); /* 00054b10 EAX */
uint8_t h2_network_game_id_matches(h2_memory *,uint32_t scratch); /* 000549d0 AL */
uint32_t h2_network_game_member_flags(h2_memory *,uint32_t index,uint32_t scratch); /* 00053be0 EAX */
uint8_t h2_network_game_member_flag2(h2_memory *,uint32_t index,uint32_t scratch); /* 00053bb0 AL */
#endif
