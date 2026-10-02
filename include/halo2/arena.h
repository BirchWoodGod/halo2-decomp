#ifndef HALO2_ARENA_H
#define HALO2_ARENA_H
#include "halo2/memory.h"
/* Platform boundaries called by original 00123b30. The backing allocation must
 * map at least 0x3fe000 writable bytes. These callbacks are not recovered code. */
typedef struct {
    void *context;
    uint32_t (*allocate)(void *,uint32_t primary_size,uint32_t extra_size);
    void (*prepare_save_storage)(void *);
    void (*protect)(void *,uint32_t address,uint32_t size,uint32_t flags);
    void (*close_save_storage)(void *);
} h2_arena_platform;
void h2_arena_initialize(h2_memory *,const h2_arena_platform *); /* 00123b30 */
void h2_arena_dispose(h2_memory *,const h2_arena_platform *); /* 00123bf0 */
void h2_arena_initialize_for_map(h2_memory *,const h2_arena_platform *); /* 00123c20 */
uint32_t h2_arena_reserve(h2_memory *,uint32_t size); /* 00123d40 */
uint32_t h2_arena_reserve_aligned(h2_memory *,uint32_t size,uint32_t alignment_bits); /* 00123d80 */
uint32_t h2_arena_allocator_allocate(h2_memory *,uint32_t size); /* 00124700 */
/* Original shared virtual release 00072c70 takes one stack argument, ignores it. */
void h2_arena_allocator_release(uint32_t address);
/* Host adapter for the arena-backed engine allocator. No per-object reclamation. */
h2_allocator h2_arena_allocator(h2_memory *);
#endif
