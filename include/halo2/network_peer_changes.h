#ifndef HALO2_NETWORK_PEER_CHANGES_H
#define HALO2_NETWORK_PEER_CHANGES_H
#include "halo2/memory.h"
/* 000602b0: EBX output, stack current/baseline, ret8, void.
 * Inputs >=0xc8 bytes; baseline may be zero. Output >=0xd8 bytes, disjoint.
 * Unchanged fields retain incoming output bytes; caller initializes flags. */
void h2_network_peer_changes(h2_memory *,uint32_t current,uint32_t baseline,uint32_t output);
#endif
