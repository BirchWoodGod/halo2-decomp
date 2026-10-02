#include "halo2/network_session_send.h"
#include "internal/memory.h"

static int64_t signed32(uint32_t v) {
    return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;
}
static uint32_t ticks(h2_memory *m,const h2_session_send_context *c) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->clock->ticks(c->clock->context);
}
static void dispatch(h2_memory *m,const h2_session_send_context *c,uint32_t session,uint32_t peer,uint8_t unreliable,uint32_t type,uint32_t size,uint32_t payload) {
    h2_network_observer_send(m,c->clock,c->send,c->codec,c->resolution,c->queue,
        h2_read32(m,session+8),h2_read32(m,peer+4),h2_read32(m,session+0x10),
        unreliable,type,size,payload,c->local,c->reliable,c->packet,c->address_workspace);
}
static uint8_t established(h2_memory *m,uint32_t session,uint32_t peer) {
    uint32_t observer=h2_read32(m,session+8),index=h2_read32(m,peer+4);
    return h2_read32(m,observer+0xa8+index*0x528)==7;
}
static void clear_transition(h2_memory *m,uint32_t session) {
    for (uint32_t i=0;i<0x7e;++i) h2_write32(m,session+0x7420+i*4,0);
}
void h2_network_session_send_peer(h2_memory *m,const h2_session_send_context *c,uint32_t session,uint32_t index,uint32_t mode,uint32_t type,uint32_t size,uint32_t payload) {
    uint32_t peer=session+0x72dc+index*20;
    if (!*h2_ptr(m,peer+1,1)) return;
    if (mode==0 || (mode==2 && established(m,session,peer)))
        dispatch(m,c,session,peer,0,type,size,payload);
    if (mode==1 || mode==2) dispatch(m,c,session,peer,1,type,size,payload);
}
void h2_network_session_broadcast(h2_memory *m,const h2_session_send_context *c,uint32_t session,uint32_t mode,uint32_t type,uint32_t size,uint32_t payload) {
    for (uint32_t i=0;signed32(i)<signed32(h2_read32(m,session+0x54));++i)
        h2_network_session_send_peer(m,c,session,i,mode,type,size,payload);
}
void h2_network_session_update_leave(h2_memory *m,const h2_session_send_context *c,uint32_t session) {
    uint32_t previous=h2_read32(m,session+0x7424);
    if (previous!=UINT32_MAX) {
        uint32_t now=ticks(m,c);
        if (signed32(now-previous)<=signed32(h2_read32(m,0x4cf4b0))) return;
    }
    h2_write32(m,c->message,h2_read32(m,session+0x1c));
    h2_write32(m,c->message+4,h2_read32(m,session+0x20));
    uint32_t peer=session+0x72dc+h2_read32(m,session+0x40)*20;
    if (*h2_ptr(m,peer+1,1)) {
        if (established(m,session,peer)) dispatch(m,c,session,peer,0,11,8,c->message);
        dispatch(m,c,session,peer,1,11,8,c->message);
    }
    h2_write32(m,session+0x7424,ticks(m,c));
}
void h2_network_session_begin_leave(h2_memory *m,const h2_session_send_context *c,uint32_t session) {
    uint32_t now=ticks(m,c);
    clear_transition(m,session);
    h2_write32(m,session+0x7420,now);
    h2_write32(m,session+0x7424,UINT32_MAX);
    h2_write32(m,session+0x741c,4);
    h2_network_session_update_leave(m,c,session);
}
void h2_network_session_begin_disband(h2_memory *m,const h2_session_send_context *c,uint32_t session) {
    h2_write32(m,c->message,h2_read32(m,session+0x1c));
    h2_write32(m,c->message+4,h2_read32(m,session+0x20));
    h2_network_session_broadcast(m,c,session,2,13,8,c->message);
    clear_transition(m,session);
    h2_write32(m,session+0x741c,6);
}
