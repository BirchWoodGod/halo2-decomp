#ifndef HALO2_ENGINE_POOLS_H
#define HALO2_ENGINE_POOLS_H
#include "halo2/memory.h"
/* Recovered original engine initialization. Memory must contain the pinned XBE
 * image, including names/globals. Host supplies only the allocator boundary. */
void h2_command_scripts_initialize(h2_memory *, const h2_allocator *); /* 00257d00 */
void h2_havok_components_initialize(h2_memory *, const h2_allocator *); /* 001cec30 */
void h2_actors_initialize(h2_memory *, const h2_allocator *); /* 001dfae0 */
#endif
