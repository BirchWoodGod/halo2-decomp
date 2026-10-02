#ifndef HALO2_DATA_ARRAY_H
#define HALO2_DATA_ARRAY_H
#include <stddef.h>
#include <stdint.h>
#include "halo2/memory.h"

/* Original Xbox addresses remain 32-bit values even on a 64-bit host.
 * This memory view is supplied by the future runtime, not an x86 interpreter.
 * Callers must supply valid engine allocations (stride >= 2, bounded capacity,
 * no arithmetic overflow). Invalid memory accesses abort instead of touching
 * unrelated host memory. No Xbox calls are needed by these routines. */

typedef struct {
    char name[32];
    uint32_t capacity, stride;
    uint8_t alignment_bits, active, flags, reserved_2b;
    uint32_t signature, allocator, next_free, high_water, count;
    uint16_t next_salt, reserved_42;
    uint32_t elements, bitmap;
} h2_data_array_layout;
_Static_assert(sizeof(h2_data_array_layout) == 0x4c, "Xbox data array layout");
_Static_assert(offsetof(h2_data_array_layout, elements) == 0x44, "Xbox pointers");
#define H2_NONE UINT32_C(0xffffffff)

/* Addresses identify original functions, not original symbol names. */
void h2_data_header_init(h2_memory *, uint32_t array, uint32_t name,
    uint32_t capacity, uint32_t stride, uint32_t alignment_bits,
    uint32_t allocator, uint32_t bitmap); /* 0016b650 */
void h2_data_init(h2_memory *, uint32_t array, uint32_t alignment_bits,
    uint32_t stride, uint32_t capacity, uint32_t name, uint32_t allocator); /* 0016b5f0 */
void h2_data_rebuild(h2_memory *, uint32_t array, uint32_t capacity, uint32_t elements); /* 0016b6b0 */
void h2_data_activate(h2_memory *, uint32_t array); /* 0016b790 */
void h2_data_clear(h2_memory *, uint32_t array); /* 0016b7a0 */
uint32_t h2_data_new(h2_memory *, uint32_t array); /* 0016b840 */
uint32_t h2_data_new_handle(h2_memory *, uint32_t array, uint32_t handle); /* 0016b910 */
uint32_t h2_data_new_at(h2_memory *, uint32_t array, uint32_t index); /* 0016b990 */
void h2_data_slot_init(h2_memory *, uint32_t array, uint32_t element); /* 0016ba00 */
void h2_data_delete(h2_memory *, uint32_t array, uint32_t handle); /* 0016ba40 */
uint32_t h2_data_get(h2_memory *, uint32_t array, uint32_t handle); /* 0016bae0 */
uint32_t h2_data_get_index(h2_memory *, uint32_t array, uint32_t index); /* 0016bb20 */
uint32_t h2_data_handle(h2_memory *, uint32_t array, uint32_t index); /* 0016bb50 */
uint32_t h2_data_iterator_next(h2_memory *, uint32_t iterator); /* 0016bb70 */
uint32_t h2_data_next(h2_memory *, uint32_t array, uint32_t handle); /* 0016bbc0 */
uint32_t h2_data_find(h2_memory *, uint32_t array, uint32_t index); /* 0016bc00 */
uint32_t h2_data_create(h2_memory *, const h2_allocator *, uint32_t identity,
    uint32_t name, uint32_t capacity, uint32_t stride, uint32_t alignment_bits); /* 0016b570 */
void h2_data_dispose(h2_memory *, const h2_allocator *, uint32_t array); /* 0016b5d0 */
#endif
