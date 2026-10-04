#ifndef HALO2_MESSAGE_PARAMETERS_ADAPTER_H
#define HALO2_MESSAGE_PARAMETERS_ADAPTER_H
#include "halo2/message_dispatch.h"
#include "halo2/format_string.h"
/* Preview host adapter; not a recovered routine or part of main dispatch.
 * Keep this context and formatter alive while the platform is used.
 * diagnostics1280 and arguments8 must be disjoint from payload/stream/storage. */
typedef struct {
    h2_native_message_codec base;
    const h2_format_operations *format;
    uint32_t diagnostics;
    uint32_t arguments;
} h2_parameters_message_codec;
uint8_t h2_parameters_message_can_encode(uint32_t function);
void h2_parameters_message_codec_init(h2_message_codec_platform *,h2_parameters_message_codec *);
#endif
