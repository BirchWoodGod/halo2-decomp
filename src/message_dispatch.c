#include "halo2/message_dispatch.h"
#include "halo2/session_description.h"
#include <stdlib.h>
typedef void (*encoder)(h2_memory *,uint32_t,uint32_t,uint32_t);
typedef uint8_t (*decoder)(h2_memory *,uint32_t,uint32_t,uint32_t);
static encoder find_encoder(uint32_t function) {
    switch (function) {
    case 0xac490: return h2_message_ping_write;
    case 0xac580: return h2_message_pong_write;
    case 0xac670: return h2_message_broadcast_search_write;
    case 0xac8a0: return h2_message_connect_request_write;
    case 0xac940: return h2_message_connect_refuse_write;
    case 0xac9e0: return h2_message_connect_establish_write;
    case 0xaca40: return h2_message_connect_closed_write;
    case 0xacc20: return h2_message_join_request_write;
    case 0xad1c0: return h2_message_join_abort_write;
    case 0xad230: return h2_message_join_refuse_write;
    case 0xad320: return h2_message_handoff_write;
    case 0xad430: return h2_message_host_decline_write;
    case 0xad5a0: return h2_message_session_id_write;
    case 0xad5c0: return h2_message_election_write;
    case 0xad820: return h2_message_election_refuse_write;
    default: return NULL;
    }
}
static decoder find_decoder(uint32_t function) {
    switch (function) {
    case 0xac530: return h2_message_ping_read;
    case 0xac610: return h2_message_pong_read;
    case 0xac6e0: return h2_message_broadcast_search_read;
    case 0xac900: return h2_message_connect_request_read;
    case 0xac9a0: return h2_message_connect_refuse_read;
    case 0xaca00: return h2_message_connect_establish_read;
    case 0xacab0: return h2_message_connect_closed_read;
    case 0xacfa0: return h2_message_join_request_read;
    case 0xad1e0: return h2_message_join_abort_read;
    case 0xad290: return h2_message_join_refuse_read;
    case 0xad2e0: return h2_message_leave_read;
    case 0xad390: return h2_message_handoff_read;
    case 0xad3f0: return h2_message_session_control_read;
    case 0xad530: return h2_message_host_decline_read;
    case 0xad710: return h2_message_election_read;
    case 0xad8d0: return h2_message_election_refuse_read;
    default: return NULL;
    }
}
uint8_t h2_message_native_can_encode(uint32_t function) {
    return function==0xac730 || function==0xad940 || find_encoder(function)!=NULL;
}
uint8_t h2_message_native_encode(h2_memory *m, const h2_network_state_operations *clock,
    uint32_t function, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch) {
    if (function==0xac730) h2_message_broadcast_reply_write(m,stream,size,payload,scratch);
    else if (function==0xad940) h2_message_time_sync_write(m,clock,stream,size,payload);
    else {
        encoder call=find_encoder(function);
        if (!call) return 0;
        call(m,stream,size,payload);
    }
    return 1;
}
int32_t h2_message_native_decode(h2_memory *m, const h2_network_state_operations *clock,
    uint32_t function, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch) {
    if (function==0xac7a0) return h2_message_broadcast_reply_read(m,stream,size,payload,scratch);
    if (function==0xad9e0) return h2_message_time_sync_read(m,clock,stream,size,payload);
    decoder call=find_decoder(function);
    return call ? call(m,stream,size,payload) : -1;
}
static void encode_callback(void *opaque, uint32_t function, uint32_t stream, uint32_t size, uint32_t payload) {
    h2_native_message_codec *codec=opaque;
    if (!h2_message_native_encode(codec->memory,codec->clock,function,stream,size,payload,codec->scratch)) abort();
}
void h2_message_native_codec_init(h2_message_codec_platform *platform, h2_native_message_codec *codec) {
    platform->context=codec;
    platform->encode=encode_callback;
}
