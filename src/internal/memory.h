#ifndef HALO2_INTERNAL_MEMORY_H
#define HALO2_INTERNAL_MEMORY_H
#include "halo2/memory.h"
#include <stdlib.h>
static inline uint8_t *h2_ptr(h2_memory *m, uint32_t a, size_t size) {
    if (a < m->base || (size_t)(a - m->base) > m->size ||
        size > m->size - (a - m->base)) abort();
    return m->bytes + (a - m->base);
}
static inline uint32_t h2_read32(h2_memory *m, uint32_t a) {
    const uint8_t *p = h2_ptr(m, a, 4);
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline void h2_write32(h2_memory *m, uint32_t a, uint32_t x) {
    uint8_t *p = h2_ptr(m, a, 4);
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(x >> (i * 8));
}
#endif
