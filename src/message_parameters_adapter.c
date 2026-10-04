#include "halo2/message_parameters_adapter.h"
#include "halo2/network_parameters_encode.h"
#include <stdlib.h>
uint8_t h2_parameters_message_can_encode(uint32_t function) {
    return function==0xaf890 || h2_message_native_can_encode(function);
}
static void encode(void *opaque,uint32_t function,uint32_t stream,uint32_t size,uint32_t payload) {
    h2_parameters_message_codec *c=opaque;
    if(function==0xaf890) {
        if(!c->format || !c->format->vsnprintf) abort();
        h2_network_parameters_encode(c->base.memory,c->format,stream,payload,c->diagnostics,c->arguments);
    } else if(!h2_message_native_encode(c->base.memory,c->base.clock,function,stream,size,payload,c->base.scratch)) abort();
}
void h2_parameters_message_codec_init(h2_message_codec_platform *platform,h2_parameters_message_codec *c) {
    platform->context=c;platform->encode=encode;
}
