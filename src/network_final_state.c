#include "halo2/network_final_state.h"
#include "internal/memory.h"
#include <string.h>

void h2_network_slot_state_initialize(h2_memory *m, uint32_t state) {
    for (uint32_t i = 0; i < 16; ++i) {
        uint32_t p = state+i*0x170;
        h2_write32(m, p+0x10, i);
        *h2_ptr(m, p+4, 1) = 1;
        h2_write32(m, p+8, 0);
        memset(h2_ptr(m, p+0xc, 2), 0, 2);
        memset(h2_ptr(m, p+0x14, 0x120), 0, 0x120);
        memset(h2_ptr(m, p+0x134, 0x40), 0, 0x40);
    }
    *h2_ptr(m, state, 1) = 1;
}

void h2_network_vector_state_initialize(h2_memory *m, uint32_t state) {
    const uint32_t offsets[] = {4,0x44,0x84,0xc8,0x108,0x194,0x1d4,0x148};
    for (unsigned i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i)
        memset(h2_ptr(m, state+offsets[i], 0x40), 0, 0x40);
    h2_write32(m, state+0x18c, UINT32_C(0xfffffc18));
    h2_write32(m, state+0x188, UINT32_C(0xffffffb0));
    *h2_ptr(m, state+0x190, 1) = 1;
    *h2_ptr(m, state, 1) = 1;
}

void h2_network_final_state_initialize(h2_memory *m) {
    memset(h2_ptr(m, 0x4c9878, 0x144), 0, 0x144);
    memset(h2_ptr(m, 0x5259bc, 0x40), 0, 0x40);
    h2_write32(m, 0x4c9878, UINT32_MAX);
    /* Other explicit zero stores in the original are inside the cleared block. */
    *h2_ptr(m, 0x5259b8, 1) = 1;
    *h2_ptr(m, 0x527104, 1) = 1;
    h2_network_slot_state_initialize(m, 0x525a00);
    h2_network_vector_state_initialize(m, 0x527108);
    *h2_ptr(m, 0x4c99b8, 1) = 1;
}
