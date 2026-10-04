#ifndef HALO2_FORMAT_STRING_H
#define HALO2_FORMAT_STRING_H
#include "halo2/memory.h"
typedef struct {
    void *context;
    void (*vsnprintf)(void *,uint32_t destination,uint32_t capacity,
        uint32_t format,uint32_t arguments);
} h2_format_operations;
/* 000b66f0: ESI destination; stack format followed by varargs; cdecl.
 * Arguments points to guest vararg words. The CRT boundary consumes these.
 * The wrapper always writes a terminator at destination+255 and returns it. */
uint32_t h2_format_string_256(h2_memory *,const h2_format_operations *,
    uint32_t destination,uint32_t format,uint32_t arguments);
#endif
