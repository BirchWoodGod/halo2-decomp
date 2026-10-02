#include "halo2/async_task_create.h"
#include "halo2/data_array.h"
#include "internal/memory.h"

uint32_t h2_async_task_create(h2_memory *m, const h2_async_task_create_platform *p,
    uint32_t kind, uint32_t count, uint32_t option, uint32_t records) {
    if (!*h2_ptr(m, 0x4cf8d4, 1)) return UINT32_MAX;
    uint32_t value = h2_read32(m, 0x440188 + kind * 4u);
    if (option == UINT32_MAX) option = h2_read32(m, 0x440190 + kind * 4u);
    if (!(count & 0x80000000u) && count > 64) count = 64;
    uint32_t scratch = p->scratch;
    if (!(count & 0x80000000u)) {
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t record = records + i * 60u;
            h2_write32(m, scratch + 0x104 + i * 4u, record);
            h2_write32(m, scratch + 0x204 + i * 4u, record + 24);
            h2_write32(m, scratch + 4 + i * 4u, record + 8);
        }
    }
    if (p->create(p->context, count, scratch + 0x204, scratch + 0x104,
                  scratch + 4, 0, 0, 0, value, option, 0, 0, scratch))
        return UINT32_MAX;
    uint32_t handle = h2_data_new(m, h2_read32(m, 0x4cf8d8));
    if (handle == UINT32_MAX) {
        p->tasks->release(p->tasks->context, h2_read32(m, scratch));
        return handle;
    }
    uint32_t pool = h2_read32(m, 0x4cf8d8);
    uint32_t entry = h2_read32(m, pool + 0x44) + (handle & 0xffff) * 8u;
    uint8_t *status = h2_ptr(m, entry + 2, 2);
    status[0] = 1;
    status[1] = 0;
    h2_write32(m, entry + 4, h2_read32(m, scratch));
    return handle;
}
