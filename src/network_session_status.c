#include "halo2/network_session_status.h"
#include "halo2/network_session.h"
#include "halo2/network_observer_retry.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_session_send_status_request(h2_memory *m,const h2_session_control_context *c,uint32_t session) {
    const h2_session_send_context *s=c->messages;
    uint32_t peer=session+h2_read32(m,session+0x40)*20+0x72dc;
    uint32_t observer=h2_read32(m,session+8),index=h2_read32(m,peer+4);
    if(h2_read32(m,observer+0xa8+index*0x528)!=7 || h2_network_session_shutdown_guard(m,session)) return;
    uint32_t previous=h2_read32(m,session+0x7654);
    if(previous!=UINT32_MAX) {
        uint32_t now=ticks(m,s->clock);
        if(sv(now-previous)<=sv(h2_read32(m,0x4cf4d8))) return;
    }
    previous=h2_read32(m,session+0x7658);
    if(previous!=UINT32_MAX) {
        uint32_t elapsed=h2_network_elapsed(m,s->clock,previous);
        if(sv(elapsed)<=sv(h2_read32(m,0x4cf4dc))) return;
    }
    uint32_t payload=c->control_message,high=h2_read32(m,session+0x20),low=h2_read32(m,session+0x1c);
    memset(h2_ptr(m,payload,28),0,28);h2_write32(m,payload,low);h2_write32(m,payload+4,high);
    for(uint32_t i=8;i<24;i+=4) h2_write32(m,payload+i,UINT32_MAX);
    h2_network_observer_send(m,s->clock,s->send,s->codec,s->resolution,s->queue,
        h2_read32(m,session+8),h2_read32(m,peer+4),h2_read32(m,session+0x10),1,24,28,
        payload,s->local,s->reliable,s->packet,s->address_workspace);
    h2_write32(m,session+0x7658,ticks(m,s->clock));
}
void h2_network_session_begin_connected(h2_memory *m,const h2_session_control_context *c,uint32_t session) {
    uint32_t now=ticks(m,c->messages->clock);
    h2_write32(m,session+0x7650,h2_read32(m,session+0x7650)+1);
    memset(h2_ptr(m,session+0x761c,52),0,52);
    h2_write32(m,session+0x7654,UINT32_MAX);h2_write32(m,session+0x7658,UINT32_MAX);
    memset(h2_ptr(m,session+0x7420,0x1f8),0,0x1f8);
    h2_write32(m,session+0x7420,now);h2_write32(m,session+0x741c,3);
    h2_network_session_send_status_request(m,c,session);
}
