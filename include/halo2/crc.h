#ifndef HALO2_CRC_H
#define HALO2_CRC_H
#include "halo2/memory.h"
void h2_crc_table_initialize(h2_memory *, uint32_t table); /* 00163c00 */
/* Raw reflected CRC accumulator: no implicit initial/final XOR. Length is signed
 * in the original ABI; zero/negative lengths still initialize the lazy table. */
void h2_crc_update(h2_memory *, uint32_t accumulator, uint32_t data, uint32_t length); /* 00163ba0 */
/* Native-call adapter for original callers' local stack buffers. */
void h2_crc_update_bytes(h2_memory *, uint32_t accumulator, const uint8_t *, uint32_t length);
#endif
