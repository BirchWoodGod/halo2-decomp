#include "halo2/bitstream_checked.h"
#include "internal/memory.h"
void h2_bitstream_write_checked(h2_memory *m, const h2_format_operations *ops,
    uint32_t stream, uint32_t value, uint32_t width,
    uint32_t diagnostic, uint32_t arguments) {
    /* CMP/JGE treats the width as signed; SHL masks the count to five bits. */
    if (width < 32 || (width & UINT32_C(0x80000000))) {
        uint32_t limit = UINT32_C(1) << (width & 31);
        if (value >= limit) {
            *h2_ptr(m, diagnostic, 1) = 0;
            h2_write32(m, arguments, value);
            h2_write32(m, arguments+4, limit);
            h2_format_string_256(m, ops, diagnostic, 0x453e78, arguments);
        }
    }
    h2_bitstream_write_bits(m, stream, value, width);
}
