#include "halo2/file_io.h"
#include "halo2/file_path.h"
#include "internal/memory.h"

uint8_t h2_file_read(h2_memory *m, const h2_file_platform *ops, uint32_t file,
                     uint32_t buffer, uint32_t count, uint8_t suppress_error) {
    uint32_t transferred = buffer;
    uint8_t success = 0;
    if (ops->read(ops->context, h2_read32(m, file+0x108), buffer, count, &transferred)) {
        if (transferred == count) success = 1;
        else ops->set_error(ops->context, 0x26);
    }
    h2_write32(m, file+0x10c, h2_read32(m, file+0x10c)+transferred);
    if (!success && !suppress_error) {
        (void)ops->last_error(ops->context);
        ops->set_error(ops->context, 0);
    }
    return success;
}

uint8_t h2_file_write(h2_memory *m, const h2_file_platform *ops, uint32_t file,
                      uint32_t buffer, uint32_t count) {
    uint32_t transferred = buffer;
    uint32_t result = ops->write(ops->context, h2_read32(m, file+0x108), buffer, count, &transferred);
    uint8_t success = result && transferred == count;
    h2_write32(m, file+0x10c, h2_read32(m, file+0x10c)+transferred);
    if (!success) {
        (void)ops->last_error(ops->context);
        ops->set_error(ops->context, 0);
    }
    return success;
}

uint8_t h2_file_close(h2_memory *m, const h2_file_platform *ops, uint32_t file) {
    if (ops->close(ops->context, h2_read32(m, file+0x108))) {
        h2_write32(m, file+0x108, 0);
        h2_write32(m, file+0x10c, 0);
        return 1;
    }
    (void)ops->last_error(ops->context);
    ops->set_error(ops->context, 0);
    return 0;
}

uint8_t h2_file_seek(h2_memory *m, const h2_file_platform *ops, uint32_t file,
                     uint32_t position, uint8_t suppress_error) {
    if (h2_read32(m, file+0x10c) == position) return 1;
    uint32_t actual = ops->seek(ops->context, h2_read32(m, file+0x108), position, 0, 0);
    h2_write32(m, file+0x10c, actual);
    if (actual == UINT32_MAX && !suppress_error) {
        (void)ops->last_error(ops->context);
        ops->set_error(ops->context, 0);
    }
    return actual != UINT32_MAX;
}

uint8_t h2_file_set_end(h2_memory *m, const h2_file_platform *ops, uint32_t file,
                        uint32_t position) {
    /* Original inlined seek failure handling is followed by a second error
     * query/reset pair on the common failure path. Preserve both pairs. */
    if (h2_file_seek(m, ops, file, position, 0) &&
        ops->set_end(ops->context, h2_read32(m, file+0x108))) return 1;
    (void)ops->last_error(ops->context);
    ops->set_error(ops->context, 0);
    return 0;
}

uint8_t h2_file_exists(h2_memory *m, const h2_file_platform *ops, uint32_t file) {
    uint8_t path[256];
    h2_file_path_resolve_buffer(m, path, file+8);
    if (ops->attributes(ops->context, path) != UINT32_MAX) return 1;
    if (ops->last_error(ops->context) != 2 && ops->last_error(ops->context) != 3) {
        (void)ops->last_error(ops->context);
        ops->set_error(ops->context, 0);
    }
    return 0;
}

uint8_t h2_file_size(h2_memory *m, const h2_file_platform *ops, uint32_t file,
                     uint32_t output) {
    uint8_t path[256], information[36];
    h2_file_path_resolve_buffer(m, path, file+8);
    if (ops->metadata(ops->context, path, 0, information)) {
        const uint8_t *p = information+32;
        h2_write32(m, output, (uint32_t)p[0] | (uint32_t)p[1]<<8 |
                   (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24);
        return 1;
    }
    (void)ops->last_error(ops->context);
    ops->set_error(ops->context, 0);
    return 0;
}

uint8_t h2_file_open(h2_memory *m, const h2_file_platform *ops, uint32_t file,
                     uint32_t flags, uint32_t error_output) {
    uint8_t path[256];
    h2_write32(m, error_output, 0);
    h2_file_path_resolve_buffer(m, path, file+8);
    uint32_t access = (flags&1) ? UINT32_C(0x80000000) : 0;
    if (flags&2) access |= UINT32_C(0x40000000);
    uint32_t sharing = (!(flags&2) || (flags&8)) ? 1 : 0;
    uint32_t attributes = 0x80;
    if (flags&0x20) attributes = 0x100;
    if (flags&0x40) attributes = 0x4000000;
    if (flags&0x80) attributes = 0x10000000;
    if (flags&0x100) attributes = 0x8000000;
    uint32_t handle = ops->open(ops->context, path, access, sharing, 0, 3, attributes, 0);
    if (handle == UINT32_MAX) {
        uint32_t error;
        switch (ops->last_error(ops->context)) {
            case 2: error=1; break;
            case 3: error=3; break;
            case 5: error=2; break;
            case 15: error=4; break;
            case 32: error=5; break;
            default: error=6; break;
        }
        h2_write32(m, error_output, error);
    } else {
        h2_write32(m, file+0x108, handle);
        h2_write32(m, file+0x10c, 0);
        if (!(flags&4)) return 1;
        uint32_t position = ops->seek(ops->context, handle, 0, 0, 2);
        h2_write32(m, file+0x10c, position);
        if (position != UINT32_MAX) return 1;
        (void)ops->close(ops->context, h2_read32(m, file+0x108));
        h2_write32(m, file+0x108, 0);
        h2_write32(m, file+0x10c, 0);
    }
    if (!(flags&0x10)) {
        (void)ops->last_error(ops->context);
        ops->set_error(ops->context, 0);
    }
    return 0;
}
