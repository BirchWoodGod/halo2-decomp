#include "halo2/file_path.h"
#include "internal/memory.h"

static uint32_t length(h2_memory *m, uint32_t path) {
    uint32_t n = 0;
    while (*h2_ptr(m, path+n, 1)) ++n;
    return n;
}

/* strncpy semantics, including zero padding, without host pointer alias rules. */
static void copy_padded(h2_memory *m, uint32_t destination, uint32_t source, uint32_t count) {
    uint8_t byte = 1;
    for (uint32_t i = 0; i < count; ++i) {
        if (byte) byte = *h2_ptr(m, source+i, 1);
        *h2_ptr(m, destination+i, 1) = byte;
    }
}

void h2_file_path_append(h2_memory *m, uint32_t destination, uint32_t component) {
    if (!*h2_ptr(m, component, 1)) return;
    uint32_t n = length(m, destination);
    if (n && *h2_ptr(m, destination+n-1, 1) != '\\') {
        *h2_ptr(m, destination+n, 1) = '\\';
        ++n;
        *h2_ptr(m, destination+n, 1) = 0;
    }
    copy_padded(m, destination+n, component, 256-n);
    *h2_ptr(m, destination+255, 1) = 0;
}

static int32_t signed16(uint32_t n) {
    n &= 0xffff;
    return n < 0x8000 ? (int32_t)n : (int32_t)n-0x10000;
}

void h2_file_path_parent(h2_memory *m, uint32_t path) {
    int32_t n = signed16(length(m, path));
    while (n > 0 && *h2_ptr(m, path+(uint32_t)n, 1) != '\\') --n;
    *h2_ptr(m, path+(uint32_t)n, 1) = 0;
}

void h2_file_path_resolve(h2_memory *m, uint32_t destination, uint32_t path) {
    *h2_ptr(m, destination, 1) = 0;
    uint8_t first = *h2_ptr(m, path, 1);
    int drive = ((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) &&
        *h2_ptr(m, path+1, 1) == ':' && *h2_ptr(m, path+2, 1) == '\\';
    if (!drive) {
        copy_padded(m, destination, 0x453588, 256);
        *h2_ptr(m, destination+255, 1) = 0;
    }
    uint32_t n = length(m, destination);
    copy_padded(m, destination+n, path, 256-n);
    *h2_ptr(m, destination+255, 1) = 0;
}

void h2_file_path_resolve_buffer(h2_memory *m, uint8_t destination[256], uint32_t path) {
    uint8_t first = *h2_ptr(m, path, 1);
    int drive = ((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) &&
        *h2_ptr(m, path+1, 1) == ':' && *h2_ptr(m, path+2, 1) == '\\';
    uint32_t n = 0;
    if (!drive) {
        while (n < 255 && (destination[n] = *h2_ptr(m, 0x453588+n, 1))) ++n;
    }
    uint8_t byte = 1;
    for (uint32_t i = 0; n < 256; ++i, ++n) {
        if (byte) byte = *h2_ptr(m, path+i, 1);
        destination[n] = byte;
    }
    destination[255] = 0;
}
