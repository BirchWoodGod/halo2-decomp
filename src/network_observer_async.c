#include "halo2/network_observer_async.h"
#include "halo2/async_task_result.h"
#include "internal/memory.h"

void h2_network_observer_async(h2_memory *m, const h2_async_task_create_platform *p,
    uint32_t observer, uint32_t index, uint32_t records) {
    uint32_t entry = observer + 0xa8 + index * 0x528u;
    if (h2_read32(m, entry) && h2_read32(m, entry + 0x70) == UINT32_MAX &&
        !(*h2_ptr(m, entry + 8, 1) & 8)) {
        uint32_t mask = *h2_ptr(m, entry + 9, 1);
        for (uint32_t i = 0; i < 4; ++i) {
            uint32_t consumer = observer + i * 36u;
            if (!(mask & (1u << i)) || h2_read32(m, consumer + 0x18) == UINT32_MAX)
                continue;
            for (uint32_t j = 0; j < 24; j += 4)
                h2_write32(m, records + j, h2_read32(m, consumer + 0x20 + j));
            for (uint32_t j = 0; j < 36; j += 4)
                h2_write32(m, records + 24 + j, h2_read32(m, entry + 0x14 + j));
            uint32_t task = h2_async_task_create(m, p, 0, 1, UINT32_MAX, records);
            h2_write32(m, entry + 0x70, task);
            break;
        }
    }
    uint32_t task = h2_read32(m, entry + 0x70);
    if (task == UINT32_MAX || !h2_async_task_is_idle(m, task)) return;
    if (h2_async_task_result(m, task, 0, entry + 0x74)) {
        *h2_ptr(m, entry + 8, 1) |= 0x10;
        h2_write32(m, entry + 0x90, 0);
        h2_write32(m, entry + 0x8c, 0);
    }
    h2_async_task_release(m, p->tasks, h2_read32(m, entry + 0x70));
    uint8_t flags = *h2_ptr(m, entry + 8, 1) | 8;
    h2_write32(m, entry + 0x70, UINT32_MAX);
    *h2_ptr(m, entry + 8, 1) = flags;
}
