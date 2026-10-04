#ifndef HALO2_NETWORK_MEMBERSHIP_ENCODE_H
#define HALO2_NETWORK_MEMBERSHIP_ENCODE_H
#include "halo2/format_string.h"
/* 000adef0: stack stream/size/message, ret12; size unused.
 * Message backing must cover both signed-count loops. Disjoint diagnostics0xd00
 * and arguments8. Reviewed; integrated into the native library. */
void h2_network_membership_encode(h2_memory *,const h2_format_operations *,uint32_t stream,uint32_t message,uint32_t diagnostics,uint32_t arguments);
#endif
