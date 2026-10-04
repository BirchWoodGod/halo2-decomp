#ifndef HALO2_NETWORK_MEMBERSHIP_SNAPSHOT_H
#define HALO2_NETWORK_MEMBERSHIP_SNAPSHOT_H
#include "halo2/memory.h"
/* 00060400: EAX session; stack current/baseline/output; ret12.
 * Current/baseline >=0x2494 bytes, peer counts 0..16, player owners in range.
 * Baseline may be zero. Output0x489c bytes must be disjoint from inputs. */
void h2_network_membership_snapshot(h2_memory *,uint32_t session,uint32_t current,uint32_t baseline,uint32_t output);
#endif
