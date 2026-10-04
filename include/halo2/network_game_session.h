#ifndef HALO2_NETWORK_GAME_SESSION_H
#define HALO2_NETWORK_GAME_SESSION_H
#include "halo2/memory.h"
/* EDX optional guest output pointer; AL success. Names identify global slots,
 * without assuming original session roles. Failure leaves output untouched. */
uint8_t h2_network_game_session_a(h2_memory *,uint32_t output); /* 00059670 */
uint8_t h2_network_game_session_b(h2_memory *,uint32_t output); /* 000596a0 */
uint8_t h2_network_game_session_selected(h2_memory *,uint32_t output); /* 00053c30 */
#endif
