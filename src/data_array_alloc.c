#include "halo2/data_array.h"
#include "internal/memory.h"
#include <string.h>

uint32_t h2_data_create(h2_memory *m, const h2_allocator *ops, uint32_t identity,
    uint32_t name, uint32_t capacity, uint32_t stride, uint32_t alignment_bits) {
    /* 0016b570. Valid engine capacities keep the signed bitmap calculation
     * nonnegative. All additions/multiplies retain 32-bit x86 wrapping. */
    uint32_t size = capacity * stride + ((capacity + 31) >> 5) * 4 +
        0x4b + (UINT32_C(1) << (alignment_bits & 31));
    uint32_t array = ops->allocate(ops->context, identity, size);
    if (array) {
        h2_data_init(m, array, alignment_bits, stride, capacity, name, identity);
        *h2_ptr(m, array + 0x2a, 1) |= 4;
    }
    return array;
}

void h2_data_dispose(h2_memory *m, const h2_allocator *ops, uint32_t array) {
    /* 0016b5d0. Read identity before clearing the entire 0x4C-byte header.
     * This routine does not check the owned flag, nor free a zero identity. */
    uint32_t identity = h2_read32(m, array + 0x30);
    memset(h2_ptr(m, array, 0x4c), 0, 0x4c);
    if (identity) ops->release(ops->context, identity, array);
}
