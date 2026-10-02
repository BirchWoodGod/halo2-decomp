#ifndef HALO2_MEMORY_H
#define HALO2_MEMORY_H
#include <stddef.h>
#include <stdint.h>

/* Guest addresses are explicit 32-bit values, independent of host pointers. */
typedef struct {
    uint8_t *bytes;
    uint32_t base;
    size_t size;
} h2_memory;

/* Host implementation of the two allocator methods used by data arrays.
 * identity is the guest allocator object, retained in the original header.
 * Callbacks may fail allocation by returning zero. Free observes the already
 * cleared header, matching 0x0016B5D0. */
typedef struct {
    void *context;
    uint32_t (*allocate)(void *context, uint32_t identity, uint32_t size);
    void (*release)(void *context, uint32_t identity, uint32_t allocation);
} h2_allocator;
#endif
