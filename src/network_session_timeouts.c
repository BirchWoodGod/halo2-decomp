#include "halo2/network_session_timeouts.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
void h2_network_session_tick_join_abort(h2_memory *m,const h2_session_control_context *c,uint32_t session) {
    const h2_session_send_context *s=c->messages;
    uint8_t cached=*h2_ptr(m,0x510548,1);
    uint32_t previous=h2_read32(m,session+0x7488);
    uint32_t now=cached ? h2_read32(m,0x51054c) : s->clock->ticks(s->clock->context);
    if(sv(now-previous)>sv(h2_read32(m,0x4cf4a4))) h2_network_session_cleanup(m,c,session);
    else h2_network_session_update_join_abort(m,s->clock,s->send,s->codec,session,c->join_message,s->packet,s->address_workspace);
}
void h2_network_session_tick_leave(h2_memory *m,const h2_session_control_context *c,uint32_t session) {
    const h2_session_send_context *s=c->messages;
    uint8_t cached=*h2_ptr(m,0x510548,1);
    uint32_t previous=h2_read32(m,session+0x7420);
    uint32_t now=cached ? h2_read32(m,0x51054c) : s->clock->ticks(s->clock->context);
    if(sv(now-previous)>sv(h2_read32(m,0x4cf4ac))) h2_network_session_cleanup(m,c,session);
    else h2_network_session_update_leave(m,s,session);
}
