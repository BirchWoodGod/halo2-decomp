#include "halo2/async_tasks.h"
#include "halo2/data_array.h"
#include "internal/memory.h"

static uint32_t lookup(h2_memory *m, uint32_t handle) {
    if (!*h2_ptr(m, 0x4cf8d4, 1) || handle == UINT32_MAX) return 0;
    uint32_t pool = h2_read32(m, 0x4cf8d8);
    uint32_t limit = h2_read32(m, pool+0x38), index = handle & 0xffff;
    if (limit & 0x80000000u || index >= limit) return 0;
    uint32_t entry = h2_read32(m, pool+0x44) + index*h2_read32(m, pool+0x24);
    const uint8_t *p = h2_ptr(m, entry, 2);
    uint32_t salt = p[0] | (uint32_t)p[1] << 8;
    return salt && salt == handle >> 16 ? entry : 0;
}

void h2_async_task_release(h2_memory *m, const h2_async_task_platform *ops, uint32_t handle) {
    uint32_t entry = lookup(m, handle);
    if (!entry) return;
    uint32_t result = ops->release(ops->context, h2_read32(m, entry+4));
    if (!result) h2_write32(m, entry+4, 0);
    h2_data_delete(m, h2_read32(m, 0x4cf8d8), handle);
}

uint8_t h2_async_task_is_idle(h2_memory *m, uint32_t handle) {
    uint32_t entry = lookup(m, handle);
    return !entry || !h2_read32(m, h2_read32(m, entry+4)+4);
}
