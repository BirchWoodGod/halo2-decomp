#ifndef HALO2_NETWORK_PARAMETER_RECORD_H
#define HALO2_NETWORK_PARAMETER_RECORD_H
#include "halo2/bitstream.h"
#include "halo2/format_string.h"
/* 0007c5a0: EAX stream, stack record, ret4. Comparisons and Xita review complete.
 * Record is at least 0x90 bytes. Disjoint diagnostic512/arguments8 scratch. */
void h2_network_parameter_record_write(h2_memory *,const h2_format_operations *,uint32_t stream,uint32_t record,uint32_t diagnostics,uint32_t arguments);
#endif
