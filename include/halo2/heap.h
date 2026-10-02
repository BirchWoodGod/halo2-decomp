#ifndef HALO2_HEAP_H
#define HALO2_HEAP_H
#include "halo2/memory.h"

/* Linux host backend, not a reconstruction of an Xbox kernel allocator.
 * One contiguous guest arena, 16-byte allocation alignment, reusable/coalescing
 * free spans. Not thread-safe yet. Game thread scheduling is still unimplemented.
 * Guest identity values are logged by callers but do not select separate arenas.
 * A runtime must route allocator identities to the appropriate heap instances. */
typedef struct h2_heap h2_heap;
h2_heap *h2_heap_create(uint32_t base, uint32_t size);
void h2_heap_destroy(h2_heap *);
h2_memory *h2_heap_memory(h2_heap *);
h2_allocator h2_heap_allocator(h2_heap *);
uint32_t h2_heap_allocate(h2_heap *, uint32_t size);
int h2_heap_release(h2_heap *, uint32_t allocation);
size_t h2_heap_live_allocations(const h2_heap *);
size_t h2_heap_bytes_in_use(const h2_heap *);
#endif
