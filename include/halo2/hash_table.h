#ifndef HALO2_HASH_TABLE_H
#define HALO2_HASH_TABLE_H
#include "halo2/memory.h"

/* Keys are 32-bit scalar values. Payload sizes, bucket counts, and node counts
 * must describe valid bounded engine allocations. Bucket count must be nonzero
 * for insert/find/remove. Callback addresses are retained as guest metadata. */
typedef struct {
    void *context;
    uint32_t (*hash)(void *,uint32_t function,uint32_t key);
    int (*equal)(void *,uint32_t function,uint32_t left,uint32_t right);
} h2_key_ops;
uint32_t h2_hash_create(h2_memory *,const h2_allocator *,uint32_t allocator,uint32_t name,
    uint32_t capacity,uint32_t payload_size,uint32_t buckets,uint32_t hash,uint32_t equal); /* 0013e1a0 */
void h2_hash_clear(h2_memory *,uint32_t table); /* 0013e210 */
uint8_t h2_hash_insert(h2_memory *,const h2_key_ops *,uint32_t table,uint32_t key,uint32_t payload); /* 0013e270 */
uint32_t h2_hash_find(h2_memory *,const h2_key_ops *,uint32_t table,uint32_t key); /* 0013e2d0 */
uint8_t h2_hash_remove(h2_memory *,const h2_key_ops *,uint32_t table,uint32_t key); /* 0013e320 */
uint32_t h2_actor_owner_hash(uint32_t key); /* 0025dd20 */
uint8_t h2_actor_owner_equal(uint32_t left,uint32_t right); /* 0025dd30 */
h2_key_ops h2_actor_owner_key_ops(void);
#endif
