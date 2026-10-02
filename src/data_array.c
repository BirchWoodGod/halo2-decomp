#include "halo2/data_array.h"
#include <stdlib.h>
#include <string.h>

/* Reconstructed from this project's original XBE and checked against its
 * instructions. Byte access avoids native alignment/endian assumptions. */
static uint8_t *ptr(h2_memory *m, uint32_t a, size_t size) {
    if (a < m->base || (size_t)(a - m->base) > m->size ||
        size > m->size - (a - m->base)) abort();
    return m->bytes + (a - m->base);
}
static uint8_t r8(h2_memory *m, uint32_t a) { return *ptr(m, a, 1); }
static uint16_t r16(h2_memory *m, uint32_t a) {
    const uint8_t *p = ptr(m, a, 2);
    return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
}
static uint32_t r32(h2_memory *m, uint32_t a) {
    const uint8_t *p = ptr(m, a, 4);
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void w8(h2_memory *m, uint32_t a, uint8_t x) { *ptr(m, a, 1) = x; }
static void w16(h2_memory *m, uint32_t a, uint16_t x) {
    uint8_t *p = ptr(m, a, 2); p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8);
}
static void w32(h2_memory *m, uint32_t a, uint32_t x) {
    uint8_t *p = ptr(m, a, 4);
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(x >> (i * 8));
}
static void fill(h2_memory *m, uint32_t a, int byte, uint32_t size) {
    memset(ptr(m, a, size), byte, size);
}
static uint32_t element(h2_memory *m, uint32_t a, uint32_t i) {
    return r32(m, a + 0x44) + i * r32(m, a + 0x24);
}
static uint32_t bit_word(h2_memory *m, uint32_t a, uint32_t i) {
    return r32(m, a + 0x48) + (i >> 5) * 4;
}
static void bit_set(h2_memory *m, uint32_t a, uint32_t i, int set) {
    uint32_t word = bit_word(m, a, i), mask = UINT32_C(1) << (i & 31);
    w32(m, word, set ? r32(m, word) | mask : r32(m, word) & ~mask);
}
static int bit_get(h2_memory *m, uint32_t a, uint32_t i) {
    return (r32(m, bit_word(m, a, i)) & (UINT32_C(1) << (i & 31))) != 0;
}
static void copy_name(h2_memory *m, uint32_t dest, uint32_t source, uint32_t n) {
    uint8_t ch = 1;
    for (uint32_t i = 0; i < n; ++i) {
        if (ch) ch = r8(m, source + i);
        w8(m, dest + i, ch);
    }
}
static void seed_salt(h2_memory *m, uint32_t a) {
    copy_name(m, a + 0x40, a, 2);
    w16(m, a + 0x40, r16(m, a + 0x40) | 0x8000);
}

void h2_data_header_init(h2_memory *m, uint32_t a, uint32_t name,
    uint32_t capacity, uint32_t stride, uint32_t align, uint32_t allocator, uint32_t bitmap) {
    fill(m, a, 0, 0x4c);
    copy_name(m, a, name, 32);
    w8(m, a + 0x1f, 0);
    w32(m, a + 0x20, capacity);
    w32(m, a + 0x24, stride);
    w8(m, a + 0x28, (uint8_t)align);
    w8(m, a + 0x2a, 3);
    w32(m, a + 0x2c, 0x64407440);
    w32(m, a + 0x30, allocator);
    w32(m, a + 0x48, bitmap);
}
void h2_data_init(h2_memory *m, uint32_t a, uint32_t align, uint32_t stride,
    uint32_t capacity, uint32_t name, uint32_t allocator) {
    uint32_t mask = (UINT32_C(1) << (align & 31)) - 1;
    uint32_t data = (a + 0x4c + mask) & ~mask;
    uint32_t bitmap = data + capacity * stride;
    h2_data_header_init(m, a, name, capacity, stride, align, allocator, bitmap);
    w8(m, a + 0x2a, r8(m, a + 0x2a) & 0xfc);
    w32(m, a + 0x44, data);
    fill(m, bitmap, 0, ((capacity + 31) >> 5) * 4);
}
void h2_data_rebuild(h2_memory *m, uint32_t a, uint32_t capacity, uint32_t data) {
    w8(m, a + 0x2a, r8(m, a + 0x2a) & 0xfd);
    w32(m, a + 0x20, capacity);
    w32(m, a + 0x44, data);
    w8(m, a + 0x29, 1);
    w32(m, a + 0x38, 0);
    w32(m, a + 0x3c, 0);
    w32(m, a + 0x34, capacity);
    seed_salt(m, a);
    for (uint32_t i = 0; i < capacity; ++i) {
        uint32_t slot = element(m, a, i);
        if (r16(m, slot)) {
            bit_set(m, a, i, 1);
            w32(m, a + 0x38, i + 1);
            w32(m, a + 0x3c, r32(m, a + 0x3c) + 1);
        } else {
            if (r8(m, a + 0x2a) & 8) {
                fill(m, slot, 0xba, r32(m, a + 0x24));
                w16(m, slot, 0);
            }
            bit_set(m, a, i, 0);
            if (i < r32(m, a + 0x34)) w32(m, a + 0x34, i);
        }
    }
}
void h2_data_clear(h2_memory *m, uint32_t a) {
    w32(m, a + 0x38, 0);
    w32(m, a + 0x3c, 0);
    w32(m, a + 0x34, 0);
    seed_salt(m, a);
    uint32_t capacity = r32(m, a + 0x20);
    if (r8(m, a + 0x2a) & 8)
        fill(m, r32(m, a + 0x44), 0xba, capacity * r32(m, a + 0x24));
    for (uint32_t i = 0; i < capacity; ++i) w16(m, element(m, a, i), 0);
    fill(m, r32(m, a + 0x48), 0, ((capacity + 31) >> 5) * 4);
}
void h2_data_activate(h2_memory *m, uint32_t a) {
    w8(m, a + 0x29, 1);
    h2_data_clear(m, a);
}
void h2_data_slot_init(h2_memory *m, uint32_t a, uint32_t slot) {
    fill(m, slot, 0, r32(m, a + 0x24));
    w16(m, slot, r16(m, a + 0x40));
    uint16_t next = (uint16_t)(r16(m, a + 0x40) + 1);
    w16(m, a + 0x40, next == 0xffff ? 0x8000 : next);
}
static void reserve_slot(h2_memory *m, uint32_t a, uint32_t i) {
    bit_set(m, a, i, 1);
    w32(m, a + 0x3c, r32(m, a + 0x3c) + 1);
    if (r32(m, a + 0x38) <= i) w32(m, a + 0x38, i + 1);
}
uint32_t h2_data_new(h2_memory *m, uint32_t a) {
    uint32_t i = r32(m, a + 0x34), limit = r32(m, a + 0x38);
    while (i < limit && bit_get(m, a, i)) ++i;
    if (i >= limit) {
        if (limit >= r32(m, a + 0x20)) return H2_NONE;
        i = limit;
    }
    reserve_slot(m, a, i);
    w32(m, a + 0x34, i + 1);
    h2_data_slot_init(m, a, element(m, a, i));
    return h2_data_handle(m, a, i);
}
uint32_t h2_data_new_at(h2_memory *m, uint32_t a, uint32_t i) {
    if ((i & 0x80000000) || i >= r32(m, a + 0x20)) return H2_NONE;
    uint32_t slot = element(m, a, i);
    if (r16(m, slot)) return H2_NONE;
    reserve_slot(m, a, i);
    h2_data_slot_init(m, a, slot);
    return h2_data_handle(m, a, i);
}
uint32_t h2_data_new_handle(h2_memory *m, uint32_t a, uint32_t handle) {
    uint32_t i = handle & 0xffff;
    if (i >= r32(m, a + 0x20)) return H2_NONE;
    uint32_t slot = element(m, a, i);
    if (r16(m, slot)) return H2_NONE;
    reserve_slot(m, a, i);
    h2_data_slot_init(m, a, slot);
    w16(m, slot, (uint16_t)(handle >> 16));
    return handle;
}
void h2_data_delete(h2_memory *m, uint32_t a, uint32_t handle) {
    uint32_t i = handle & 0xffff, slot = element(m, a, i);
    if (r8(m, a + 0x2a) & 8) fill(m, slot, 0xba, r32(m, a + 0x24));
    bit_set(m, a, i, 0);
    w16(m, slot, 0);
    if (i < r32(m, a + 0x34)) w32(m, a + 0x34, i);
    uint32_t high = r32(m, a + 0x38);
    if (i + 1 == high) {
        do { --high; } while (high && !r16(m, element(m, a, high - 1)));
        w32(m, a + 0x38, high);
    }
    w32(m, a + 0x3c, r32(m, a + 0x3c) - 1);
}
uint32_t h2_data_get(h2_memory *m, uint32_t a, uint32_t handle) {
    uint32_t i = handle & 0xffff;
    if (handle == H2_NONE || i >= r32(m, a + 0x38)) return 0;
    uint32_t slot = element(m, a, i);
    uint16_t salt = r16(m, slot);
    return salt && salt == (handle >> 16) ? slot : 0;
}
uint32_t h2_data_get_index(h2_memory *m, uint32_t a, uint32_t i) {
    if ((i & 0x80000000) || i >= r32(m, a + 0x38)) return 0;
    uint32_t slot = element(m, a, i);
    return r16(m, slot) ? slot : 0;
}
uint32_t h2_data_handle(h2_memory *m, uint32_t a, uint32_t i) {
    return i == H2_NONE ? H2_NONE : ((uint32_t)r16(m, element(m, a, i)) << 16) | i;
}
uint32_t h2_data_find(h2_memory *m, uint32_t a, uint32_t i) {
    if (i & 0x80000000) return H2_NONE;
    for (; i < r32(m, a + 0x38); ++i) if (bit_get(m, a, i)) return i;
    return H2_NONE;
}
uint32_t h2_data_iterator_next(h2_memory *m, uint32_t iterator) {
    uint32_t a = r32(m, iterator);
    uint32_t i = h2_data_find(m, a, r32(m, iterator + 8) + 1);
    if (i == H2_NONE) {
        w32(m, iterator + 8, r32(m, a + 0x20));
        w32(m, iterator + 4, H2_NONE);
        return 0;
    }
    w32(m, iterator + 8, i);
    w32(m, iterator + 4, h2_data_handle(m, a, i));
    return element(m, a, i);
}
uint32_t h2_data_next(h2_memory *m, uint32_t a, uint32_t handle) {
    uint32_t i = h2_data_find(m, a, handle == H2_NONE ? 0 : (handle & 0xffff) + 1);
    return h2_data_handle(m, a, i);
}
