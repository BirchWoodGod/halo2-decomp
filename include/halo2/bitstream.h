#ifndef HALO2_BITSTREAM_H
#define HALO2_BITSTREAM_H
#include "halo2/memory.h"
uint8_t h2_bitstream_read_bool(h2_memory *, uint32_t stream); /* 001957d0 */
uint8_t h2_bitstream_has_error(h2_memory *, uint32_t stream); /* 001946f0 */
void h2_bitstream_pop_checkpoint(h2_memory *, uint32_t stream, uint8_t rollback); /* 00194710 */
/* Guest buffers must include the word padding touched by the original code. */
uint32_t h2_bitstream_read_bits(h2_memory *, uint32_t stream, uint32_t count); /* 001959c0 */
void h2_bitstream_write_bits(h2_memory *, uint32_t stream, uint32_t value, uint32_t count); /* 00195720 */
void h2_bitstream_read_buffer(h2_memory *, uint32_t stream, uint32_t destination, uint32_t count); /* 00195820 */
void h2_bitstream_write_buffer(h2_memory *, uint32_t stream, uint32_t source, uint32_t count); /* 001955d0 */
#endif
