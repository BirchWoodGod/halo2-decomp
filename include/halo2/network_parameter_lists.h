#ifndef HALO2_NETWORK_PARAMETER_LISTS_H
#define HALO2_NETWORK_PARAMETER_LISTS_H
#include "halo2/bitstream.h"
#include "halo2/format_string.h"
/* 00063690: stack block/stream, ret8.
 * Disjoint diagnostics768 and arguments8 replace original stack buffers.
 * Caller supplies storage for every entry addressed by signed positive counts. */
void h2_network_parameter_lists_write(h2_memory *,const h2_format_operations *,uint32_t block,uint32_t stream,uint32_t diagnostics,uint32_t arguments);
#endif
