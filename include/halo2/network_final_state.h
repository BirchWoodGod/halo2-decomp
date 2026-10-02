#ifndef HALO2_NETWORK_FINAL_STATE_H
#define HALO2_NETWORK_FINAL_STATE_H
#include "halo2/memory.h"
/* Descriptive names; original subsystem and structure names are unknown. */
void h2_network_slot_state_initialize(h2_memory *, uint32_t state); /* 00056080 */
void h2_network_vector_state_initialize(h2_memory *, uint32_t state); /* 00056ae0 */
void h2_network_final_state_initialize(h2_memory *); /* 00053210 */
#endif
