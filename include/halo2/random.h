#ifndef HALO2_RANDOM_H
#define HALO2_RANDOM_H
#include "halo2/memory.h"
/* External CRT/SDK entropy sources, in their original call order. */
typedef struct {
    void *context;
    uint32_t (*time_value)(void *);
    uint32_t (*crt_random)(void *);
    uint32_t (*tick_value)(void *);
} h2_random_sources;
void h2_random_initialize(h2_memory *,const h2_random_sources *); /* 00146240 */
uint32_t h2_random_generate_seed(const h2_random_sources *); /* 001462b0 */
void h2_random_direction(h2_memory *,uint32_t output,uint32_t seed); /* 001462e0 */
void h2_lifecycle_noop(void); /* 00175f40: shared RET stub */
/* SDK random-byte boundary; the callback receives the original guest buffer
 * and raw 32-bit count. Its return value is ignored by the engine. */
typedef struct {
    void *context;
    void (*fill)(void *,uint32_t output,uint32_t count);
} h2_random_bytes_platform;
void h2_random_bytes(h2_memory *,const h2_random_sources *,const h2_random_bytes_platform *,uint32_t output,uint32_t count); /* 0007ad80 */
void h2_random_identity(h2_memory *,const h2_random_sources *,const h2_random_bytes_platform *,uint32_t output); /* 0007ad50 */
#endif
