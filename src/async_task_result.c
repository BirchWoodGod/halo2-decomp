#include "halo2/async_task_result.h"
#include "internal/memory.h"

static uint32_t word(h2_memory *m, uint32_t address) {
    const uint8_t *p = h2_ptr(m, address, 2);
    return p[0] | (uint32_t)p[1] << 8;
}

uint8_t h2_async_task_result(h2_memory *m, uint32_t handle, uint32_t index,
                             uint32_t out) {
    if (!*h2_ptr(m, 0x4cf8d4, 1) || handle == UINT32_MAX) return 0;
    uint32_t pool = h2_read32(m, 0x4cf8d8);
    uint32_t limit = h2_read32(m, pool + 0x38), slot = handle & 0xffff;
    if ((limit & 0x80000000u) || slot >= limit) return 0;
    uint32_t entry = h2_read32(m, pool + 0x44) + slot * h2_read32(m, pool + 0x24);
    uint32_t salt = word(m, entry);
    if (!salt || salt != handle >> 16) return 0;
    uint32_t record = h2_read32(m, entry + 4) + index * 24u + 8u;
    uint8_t flags = *h2_ptr(m, record, 1);
    if (!(flags & 2) || !(flags & 0x11)) return 0;
    /* Keep instruction order: output may overlap the result record. */
    for (uint32_t i = 0; i < 32; i += 4) h2_write32(m, out + i, 0);
    h2_write32(m, out, word(m, record + 2));
    h2_write32(m, out + 4, word(m, record + 4));
    h2_write32(m, out + 8, word(m, record + 12));
    h2_write32(m, out + 12, word(m, record + 14));
    h2_write32(m, out + 16, h2_read32(m, record + 16));
    h2_write32(m, out + 20, h2_read32(m, record + 20));
    if (*h2_ptr(m, record, 1) & 8) {
        h2_write32(m, out + 24, word(m, record + 6));
        h2_write32(m, out + 28, h2_read32(m, record + 8));
    }
    return 1;
}
