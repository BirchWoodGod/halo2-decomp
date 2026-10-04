#ifndef HALO2_NETWORK_PARAMETERS_ENCODE_H
#define HALO2_NETWORK_PARAMETERS_ENCODE_H
#include "halo2/format_string.h"
/* 000af890: stack stream/size/message, ret12, void; size is unused.
 * Message >=0x14d8 bytes. Disjoint diagnostics1280 and arguments8.
 * Requires valid variant tags and backing storage for parameter-list counts.
 * Composed comparisons and original/Xita reviews completed. */
void h2_network_parameters_encode(h2_memory *,const h2_format_operations *,
    uint32_t stream,uint32_t message,uint32_t diagnostics,uint32_t arguments);
#endif
