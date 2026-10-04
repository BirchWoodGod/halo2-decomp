#ifndef HALO2_NETWORK_SESSION_PEER_LOOKUP_H
#define HALO2_NETWORK_SESSION_PEER_LOOKUP_H
#include "halo2/memory.h"
/* 00063ba0: ECX table, EDX identity; EAX last matching index or UINT32_MAX.
 * Six-byte entries begin at table+0x58; signed count at +0x54. */
uint32_t h2_network_session_find_peer_identity(h2_memory *,uint32_t table,uint32_t identity);
#endif
