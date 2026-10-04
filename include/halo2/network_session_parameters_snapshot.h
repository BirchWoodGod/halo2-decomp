#ifndef HALO2_NETWORK_SESSION_PARAMETERS_SNAPSHOT_H
#define HALO2_NETWORK_SESSION_PARAMETERS_SNAPSHOT_H
#include "halo2/memory.h"
/* Preview 000609e0: EAX session, EBX current, stack baseline/output, ret8.
 * Baseline may be zero. Output is 0x14d8 bytes and must be disjoint from inputs.
 * Current/baseline each provide at least 0x14ac bytes. */
void h2_network_session_build_parameters_snapshot(h2_memory *,uint32_t session,uint32_t current,uint32_t baseline,uint32_t output);
#endif
