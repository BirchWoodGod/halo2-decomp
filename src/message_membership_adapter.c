#include "halo2/message_membership_adapter.h"
#include "halo2/network_membership_encode.h"
#include <stdlib.h>
uint8_t h2_membership_message_can_encode(uint32_t function) {
    return function==0xadef0 || h2_parameters_message_can_encode(function);
}
static void encode(void *opaque,uint32_t function,uint32_t stream,uint32_t size,uint32_t payload) {
    h2_parameters_message_codec *c=opaque;
    if(function==0xadef0) {
        if(!c->format || !c->format->vsnprintf) abort();
        h2_network_membership_encode(c->base.memory,c->format,stream,payload,c->diagnostics,c->arguments);
    } else {
        h2_message_codec_platform delegate;
        h2_parameters_message_codec_init(&delegate,c);
        delegate.encode(delegate.context,function,stream,size,payload);
    }
}
void h2_membership_message_codec_init(h2_message_codec_platform *platform,h2_parameters_message_codec *c) {
    platform->context=c;platform->encode=encode;
}
