#ifndef HALO2_NETWORK_PARAMETER_VARIANT_H
#define HALO2_NETWORK_PARAMETER_VARIANT_H
#include "halo2/bitstream_checked.h"
/* 0007cc50: stack stream/record, ret8, void. Record >=0x10c bytes.
 * Disjoint diagnostics512 and arguments8. Tags 0,1,2,3,4,7,8,9 only;
 * other dispatch values fault in the original and are unsupported here. */
void h2_network_parameter_variant_write(h2_memory *, const h2_format_operations *,
    uint32_t stream, uint32_t record, uint32_t diagnostics, uint32_t arguments);
#endif
