#ifndef HALO2_NETWORK_PARAMETER_BLOCK_H
#define HALO2_NETWORK_PARAMETER_BLOCK_H
#include "halo2/bitstream.h"
#include "halo2/format_string.h"
/* 000b2330: EAX block68, EBX stream, void.
 * Disjoint diagnostic256 and arguments8 replace original stack storage. */
void h2_network_parameter_block_write(h2_memory *,const h2_format_operations *,uint32_t stream,uint32_t block,uint32_t diagnostic,uint32_t arguments);
#endif
