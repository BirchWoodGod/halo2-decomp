#ifndef HALO2_MESSAGE_MEMBERSHIP_ADAPTER_H
#define HALO2_MESSAGE_MEMBERSHIP_ADAPTER_H
#include "halo2/message_parameters_adapter.h"
/* Preview extension: same context layout, diagnostics must have0xd00 bytes and
 * arguments8, disjoint. Handles type25 and delegates all others to parameter adapter. */
uint8_t h2_membership_message_can_encode(uint32_t function);
void h2_membership_message_codec_init(h2_message_codec_platform *,h2_parameters_message_codec *);
#endif
