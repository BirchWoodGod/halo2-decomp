#include "halo2/network_config.h"
#include "halo2/file_path.h"
#include "halo2/crc.h"
#include "internal/memory.h"
#include <string.h>

void h2_network_config_defaults(h2_memory *m) {
    h2_write32(m, 0x4cf974, 0);
    h2_write32(m, 0x4cf978, 0);
    h2_write32(m, 0x4cf970, 8);
    for (uint32_t p = 0x4cf97c; p <= 0x4cf988; p += 4)
        h2_write32(m, p, UINT32_MAX);
    for (uint32_t i = 0; i < 350; ++i) {
        uint32_t p = 0x4cf98c+i*0x68;
        memset(h2_ptr(m, p, 0x68), 0, 0x68);
        *h2_ptr(m, p+0x56, 1) = 0xff;
        memset(h2_ptr(m, p+0x58, 8), 0xff, 8);
    }
}

uint8_t h2_network_config_fields_valid(h2_memory *m, uint32_t fields) {
    const uint8_t *p = h2_ptr(m, fields, 8);
    for (unsigned i = 0; i < 4; ++i)
        if (p[i] != 0xff && p[i] >= 18) return 0;
    return (p[4] == 0xff || p[4] < 4) &&
           p[5] < 64 && p[6] < 32 && (p[7]&0xf0) == 0;
}

static uint32_t read16(h2_memory *m, uint32_t address) {
    const uint8_t *p = h2_ptr(m, address, 2);
    return (uint32_t)p[0] | (uint32_t)p[1]<<8;
}

static int index_valid(uint32_t index, uint32_t count) {
    return index == UINT32_MAX || index < count;
}

static int chain_valid(h2_memory *m, uint32_t count, uint32_t head,
                       uint32_t tail, uint32_t offset) {
    if (head == UINT32_MAX) return 1;
    uint32_t seen[11] = {0};
    uint32_t current = head;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t bit = UINT32_C(1) << (current&31);
        if (seen[current>>5]&bit) return 0;
        seen[current>>5] |= bit;
        uint32_t p = 0x4cf98c+current*0x68;
        uint32_t previous = read16(m, p+offset);
        if (i == 0 ? previous != 0xffff : previous >= count) return 0;
        uint32_t next = read16(m, p+offset+2);
        if (i+1 == count) return next == 0xffff && current == tail;
        if (next >= count) return 0;
        if (read16(m, 0x4cf98c+next*0x68+offset) != current) return 0;
        current = next;
    }
    return 1;
}

uint8_t h2_network_config_validate(h2_memory *m) {
    uint32_t count = h2_read32(m, 0x4cf978);
    if (h2_read32(m, 0x4cf970) != 8 || count > 350) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t p = 0x4cf98c+i*0x68;
        if (i && memcmp(h2_ptr(m, p-0x68, 12), h2_ptr(m, p, 12), 12) >= 0)
            return 0;
        if (!h2_network_config_fields_valid(m, p+0x4c)) return 0;
        uint32_t value = h2_read32(m, p+8);
        if ((value&3) || value == UINT32_C(0xbad00000)) return 0;
    }
    uint32_t a = h2_read32(m, 0x4cf97c), b = h2_read32(m, 0x4cf980);
    uint32_t c = h2_read32(m, 0x4cf984), d = h2_read32(m, 0x4cf988);
    if (((a == UINT32_MAX) != (b == UINT32_MAX)) ||
        ((c == UINT32_MAX) != (d == UINT32_MAX)) ||
        !index_valid(a,count) || !index_valid(b,count) ||
        !index_valid(c,count) || !index_valid(d,count)) return 0;
    return chain_valid(m, count, a, b, 0x5c) && chain_valid(m, count, c, d, 0x58);
}

uint8_t h2_network_config_load(h2_memory *m, const h2_file_platform *ops,
                               uint32_t workspace) {
    uint32_t file = workspace+4;
    memset(h2_ptr(m, file, 0x110), 0, 0x110);
    h2_write32(m, file, UINT32_C(0x66696c6f));
    memset(h2_ptr(m, file+6, 2), 0xff, 2);
    /* The just-cleared reference has no previous final path component. */
    h2_file_path_append(m, file+8, 0x450c68);
    *h2_ptr(m, file+4, 1) |= 1;
    if (!h2_file_exists(m, ops, file)) return 0;
    h2_write32(m, workspace, 0);
    if (!h2_file_size(m, ops, file, workspace) || h2_read32(m, workspace) != 0x8e4c)
        return 0;
    if (!h2_file_open(m, ops, file, 1, workspace)) return 0;
    uint8_t success = 0;
    if (h2_file_read(m, ops, file, 0x4cf970, 0x8e4c, 1)) {
        h2_write32(m, workspace, UINT32_MAX);
        h2_crc_update(m, workspace, 0x4cf978, 0x8e44);
        if (h2_read32(m, workspace) == h2_read32(m, 0x4cf974))
            success = h2_network_config_validate(m);
    }
    (void)h2_file_close(m, ops, file);
    return success;
}
