#ifndef HALO2_MESSAGE_DISPATCH_H
#define HALO2_MESSAGE_DISPATCH_H
#include "halo2/network_messages.h"
/* Native host integration, not additional recovered Xbox routines.
 * Addresses are callback identifiers, never executed as guest instructions.
 * Unknown encoders return 0, unknown decoders -1, with no memory changes.
 * Known decoders return their original 0/1 validity result. */
uint8_t h2_message_native_can_encode(uint32_t function);
uint8_t h2_message_native_encode(h2_memory *, const h2_network_state_operations *,
    uint32_t function, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch);
int32_t h2_message_native_decode(h2_memory *, const h2_network_state_operations *,
    uint32_t function, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch);
/* Keep this context alive as long as the returned platform is used.
 * Clock callbacks are required for time-sync messages. Broadcast-reply scratch
 * follows session_description.h (64 bytes encode, 76 decode), including its
 * incoming-byte and disjointness requirements. The queue adapter fails fast
 * on an unsupported encoder, since its original void callback cannot report
 * failure; preflight descriptor addresses with can_encode before enqueue. */
typedef struct {
    h2_memory *memory;
    const h2_network_state_operations *clock;
    uint32_t scratch;
} h2_native_message_codec;
void h2_message_native_codec_init(h2_message_codec_platform *, h2_native_message_codec *);
#endif
