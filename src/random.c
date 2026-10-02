#include "halo2/random.h"
#include "halo2/arena.h"
#include "internal/memory.h"
uint32_t h2_random_generate_seed(const h2_random_sources *sources) {
    uint32_t a=sources->time_value(sources->context);
    uint32_t b=sources->crt_random(sources->context);
    uint32_t c=sources->tick_value(sources->context);
    return a^b^c;
}
void h2_random_initialize(h2_memory *m,const h2_random_sources *sources) {
    uint32_t state=h2_arena_reserve(m,8);
    h2_write32(m,0x4e7408,state);
    h2_write32(m,state,0x78a8);
    uint32_t seed=h2_random_generate_seed(sources);
    h2_write32(m,h2_read32(m,0x4e7408)+4,seed);
}
void h2_random_direction(h2_memory *m,uint32_t output,uint32_t seed) {
    uint32_t next=h2_read32(m,seed)*UINT32_C(0x19660d)+UINT32_C(0x3c6ef35f);
    h2_write32(m,seed,next);
    uint32_t index=((next>>16)*0x402)>>16;
    uint32_t source=0x4417f0+index*12;
    for (uint32_t i=0;i<12;i+=4) h2_write32(m,output+i,h2_read32(m,source+i));
}
void h2_lifecycle_noop(void) {}

void h2_random_bytes(h2_memory *m,const h2_random_sources *sources,
    const h2_random_bytes_platform *platform,uint32_t output,uint32_t count) {
    if (*h2_ptr(m,0x4cf790,1)) {
        platform->fill(platform->context,output,count);
        return;
    }
    uint32_t seed=h2_random_generate_seed(sources);
    /* Original signed loop bound: entropy is still acquired for count <= 0. */
    if (count&0x80000000u) return;
    for (uint32_t i=0;i<count;++i) {
        seed=seed*UINT32_C(0x19660d)+UINT32_C(0x3c6ef35f);
        *h2_ptr(m,output+i,1)=(uint8_t)(seed>>24);
    }
}
void h2_random_identity(h2_memory *m,const h2_random_sources *sources,
    const h2_random_bytes_platform *platform,uint32_t output) {
    for (;;) {
        h2_random_bytes(m,sources,platform,output,8);
        uint32_t empty=h2_read32(m,0x46725c);
        if (h2_read32(m,empty)!=h2_read32(m,output) ||
            h2_read32(m,empty+4)!=h2_read32(m,output+4)) return;
    }
}
