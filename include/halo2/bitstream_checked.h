#ifndef HALO2_BITSTREAM_CHECKED_H
#define HALO2_BITSTREAM_CHECKED_H
#include "halo2/bitstream.h"
#include "halo2/format_string.h"
/* 001947e0: EBX value, EDI width, stack stream; ret4, void.
 * Diagnostic256 and arguments8 must be disjoint from stream and its storage. */
void h2_bitstream_write_checked(h2_memory *, const h2_format_operations *,
    uint32_t stream, uint32_t value, uint32_t width,
    uint32_t diagnostic, uint32_t arguments);
#endif
