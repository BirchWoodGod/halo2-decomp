#include "halo2/bitstream.h"
#include "internal/memory.h"
#include <string.h>

static int64_t signed32(uint32_t value) {
    return value & 0x80000000u ? (int64_t)value-INT64_C(0x100000000) : value;
}
uint8_t h2_bitstream_read_bool(h2_memory *m, uint32_t stream) {
    uint32_t position=h2_read32(m,stream+16);
    uint8_t value=0;
    /* The original includes the capacity boundary, reading one padding bit. */
    if (signed32(position)<=signed32(h2_read32(m,stream+4)<<3)) {
        uint32_t byte=(uint32_t)(signed32(position)/8);
        uint32_t shift=(uint32_t)(signed32(position)%8)&31;
        value=(*h2_ptr(m,h2_read32(m,stream)+byte,1)&(uint8_t)(1u<<shift))!=0;
    }
    h2_write32(m,stream+16,position+1);
    return value;
}
uint8_t h2_bitstream_has_error(h2_memory *m, uint32_t stream) {
    return *h2_ptr(m, stream+0x14, 1) != 0 ||
        signed32(h2_read32(m, stream+0x10)) > signed32(h2_read32(m, stream+4) << 3);
}
void h2_bitstream_pop_checkpoint(h2_memory *m, uint32_t stream, uint8_t rollback) {
    uint32_t depth = h2_read32(m, stream+0x18)-1;
    h2_write32(m, stream+0x18, depth);
    uint32_t saved = h2_read32(m, stream+0x1c+depth*4);
    if (!rollback) return;
    if (h2_read32(m, stream+0xc) == 1) {
        uint32_t position = h2_read32(m, stream+0x10);
        if (signed32(saved) < signed32(position)) {
            h2_write32(m, stream+0x2c, position-saved);
            uint32_t byte = (uint32_t)(signed32(saved)/8);
            uint32_t size = h2_read32(m, stream+4);
            h2_write32(m, stream+0x30, h2_read32(m, stream+0x30)+1);
            if (signed32(byte) < signed32(size)) {
                uint32_t address = h2_read32(m, stream)+byte;
                uint32_t shift = (uint32_t)(signed32(saved)%8) & 31;
                *h2_ptr(m, address, 1) &= (uint8_t)((1u << shift)-1);
            }
            uint32_t remaining = h2_read32(m, stream+4)-byte-1;
            if (signed32(remaining) > 0)
                memset(h2_ptr(m, h2_read32(m, stream)+byte+1, remaining), 0, remaining);
        }
    }
    h2_write32(m, stream+0x10, saved);
}

static uint32_t sar5(uint32_t x) {
    return (x >> 5) | (x & 0x80000000u ? 0xf8000000u : 0);
}
static uint32_t available_bits(h2_memory *m, uint32_t stream, uint32_t position, uint32_t count) {
    uint32_t remaining = (h2_read32(m, stream+4) << 3)-position;
    return (remaining ^ 0x80000000u) <= (count ^ 0x80000000u) ? remaining : count;
}
uint32_t h2_bitstream_read_bits(h2_memory *m, uint32_t stream, uint32_t count) {
    uint32_t position = h2_read32(m, stream+0x10), result = 0;
    uint32_t actual = available_bits(m, stream, position, count);
    if (actual && !(actual & 0x80000000u)) {
        uint32_t index = sar5(position), shift = position & 31;
        uint32_t address = h2_read32(m, stream)+index*4;
        result = h2_read32(m, address) >> shift;
        if (index != sar5(position+actual-1))
            result |= h2_read32(m, address+4) << ((32-shift) & 31);
        result &= UINT32_MAX >> ((32-actual) & 31);
    }
    h2_write32(m, stream+0x10, position+count);
    return result;
}
void h2_bitstream_write_bits(h2_memory *m, uint32_t stream, uint32_t value, uint32_t count) {
    uint32_t position = h2_read32(m, stream+0x10);
    uint32_t actual = available_bits(m, stream, position, count);
    if (actual && !(actual & 0x80000000u)) {
        uint32_t index = sar5(position), shift = position & 31;
        uint32_t address = h2_read32(m, stream)+index*4;
        value &= UINT32_MAX >> ((32-actual) & 31);
        h2_write32(m, address, h2_read32(m, address) | (value << shift));
        if (index != sar5(position+actual-1))
            h2_write32(m, h2_read32(m, stream)+index*4+4, value >> ((32-shift) & 31));
    }
    h2_write32(m, stream+0x10, h2_read32(m, stream+0x10)+count);
}

static uint32_t sar3(uint32_t x) {
    return (x >> 3) | (x & 0x80000000u ? 0xe0000000u : 0);
}
/* REP MOVSD then REP MOVSB: preserve forward-copy behavior for overlaps. */
static void forward_copy(h2_memory *m, uint32_t destination, uint32_t source, uint32_t bytes) {
    uint32_t words = bytes >> 2;
    for (uint32_t i = 0; i < words; ++i)
        h2_write32(m, destination+i*4, h2_read32(m, source+i*4));
    for (uint32_t i = words*4; i < bytes; ++i)
        *h2_ptr(m, destination+i, 1) = *h2_ptr(m, source+i, 1);
}
void h2_bitstream_write_buffer(h2_memory *m, uint32_t stream, uint32_t source, uint32_t count) {
    uint32_t position = h2_read32(m, stream+0x10);
    uint32_t actual = available_bits(m, stream, position, count);
    if (actual && !(actual & 0x80000000u)) {
        if (!(position & 7)) {
            forward_copy(m, h2_read32(m, stream)+sar3(position), source, sar3(actual+7));
            uint32_t end = h2_read32(m, stream+0x10)+actual, remainder = end & 7;
            if (remainder) *h2_ptr(m, h2_read32(m, stream)+sar3(end), 1) &= (uint8_t)(255u >> (8-remainder));
        } else {
            uint32_t base = h2_read32(m, stream), shift = position & 31;
            uint32_t end = base+sar5(position+actual-1)*4+4;
            uint32_t destination = base+sar5(position)*4;
            h2_write32(m, destination, h2_read32(m, destination) | (h2_read32(m, source) << shift));
            destination += 4;
            while (destination < end) {
                uint32_t value = h2_read32(m, source) >> ((32-shift)&31);
                source += 4;
                h2_write32(m, destination, value);
                value = h2_read32(m, source) << shift;
                h2_write32(m, destination, h2_read32(m, destination) | value);
                destination += 4;
            }
            uint32_t bit_end = h2_read32(m, stream+0x10)+actual, remainder = bit_end & 31;
            if (remainder) {
                uint32_t address = h2_read32(m, stream)+sar5(bit_end)*4;
                h2_write32(m, address, h2_read32(m, address) & (UINT32_MAX >> (32-remainder)));
            }
        }
    }
    h2_write32(m, stream+0x10, h2_read32(m, stream+0x10)+count);
}
void h2_bitstream_read_buffer(h2_memory *m, uint32_t stream, uint32_t destination, uint32_t count) {
    uint32_t position = h2_read32(m, stream+0x10);
    uint32_t actual = available_bits(m, stream, position, count);
    if (actual && !(actual & 0x80000000u)) {
        if (!(position & 7)) {
            forward_copy(m, destination, h2_read32(m, stream)+sar3(position), sar3(actual+7));
            uint32_t remainder = actual & 7;
            if (remainder) *h2_ptr(m, destination+sar3(actual), 1) &= (uint8_t)(255u >> (8-remainder));
        } else {
            uint32_t source = h2_read32(m, stream)+sar5(position)*4, shift = position & 31;
            uint32_t end = destination+sar5(actual-1)*4+4, remainder = actual & 31;
            uint32_t tail = destination+sar5(actual)*4, preserved = 0;
            uint32_t tail_bytes = (remainder+7) >> 3;
            if (remainder && tail_bytes < 4)
                preserved = h2_read32(m, tail) & (UINT32_MAX << (tail_bytes*8));
            for (uint32_t p = destination; p < end; p += 4) {
                uint32_t value = h2_read32(m, source) >> shift;
                source += 4;
                h2_write32(m, p, value);
                value = h2_read32(m, source) << ((32-shift)&31);
                h2_write32(m, p, h2_read32(m, p) | value);
            }
            if (remainder) h2_write32(m, tail, (h2_read32(m, tail) & (UINT32_MAX >> (32-remainder))) | preserved);
        }
    }
    h2_write32(m, stream+0x10, h2_read32(m, stream+0x10)+count);
}
