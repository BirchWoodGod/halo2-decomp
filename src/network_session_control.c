#include "halo2/network_session_control.h"
#include "halo2/network_session.h"
#include "internal/memory.h"
#include <stdlib.h>

static int64_t signed32(uint32_t v) {
    return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;
}
static void zero_words(h2_memory *m,uint32_t address,uint32_t count) {
    for (uint32_t i=0;i<count;++i) h2_write32(m,address+i*4,0);
}
void h2_network_session_begin_handoff(h2_memory *m,const h2_session_control_context *c,uint32_t session,uint8_t flag,uint32_t peer) {
    if (signed32(h2_read32(m,session+0x54))<=1) {
        if (flag) h2_network_session_request_shutdown(m,c,session,1);
        return;
    }
    uint32_t local=c->handoff;
    zero_words(m,local,9);
    *h2_ptr(m,local,1)=flag;
    h2_write32(m,local+12,UINT32_MAX);
    const h2_network_state_operations *clock=c->messages->clock;
    uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,local+8,now);
    uint32_t mask;
    if (peer==UINT32_MAX) {
        uint32_t local_peer=h2_read32(m,session+0x72d8),count=h2_read32(m,session+0x54);
        mask=~(UINT32_C(1)<<(local_peer&31))&((UINT32_C(1)<<(count&31))-1);
    } else mask=UINT32_C(1)<<(peer&31);
    h2_write32(m,local+4,mask);
    zero_words(m,session+0x7420,0x7e);
    for (uint32_t i=0;i<9;++i) h2_write32(m,session+0x7420+i*4,h2_read32(m,local+i*4));
    h2_write32(m,session+0x741c,7);
}
void h2_network_session_request_shutdown(h2_memory *m,const h2_session_control_context *c,uint32_t session,uint8_t force) {
    uint32_t state=h2_read32(m,session+0x741c);
    if (!state || h2_network_session_shutdown_guard(m,session) || *h2_ptr(m,session+0x48,1)) return;
    const h2_session_send_context *s=c->messages;
    switch (state) {
    case 1:
        h2_network_session_begin_join_abort(m,s->clock,s->send,s->codec,session,c->join_saved,c->join_message,s->packet,s->address_workspace);
        return;
    case 3:h2_network_session_begin_leave(m,s,session);return;
    case 5:case 7:
        if (force) h2_network_session_begin_disband(m,s,session);
        else if (state==7) *h2_ptr(m,session+0x7420,1)=1;
        else h2_network_session_begin_handoff(m,c,session,1,UINT32_MAX);
        return;
    case 8:*h2_ptr(m,session+0x7420,1)=1;return;
    case 9:
        if (force) {
            uint32_t high=h2_read32(m,session+0x20),payload=c->control_message;
            zero_words(m,payload,13);
            h2_write32(m,payload,h2_read32(m,session+0x1c));
            h2_write32(m,payload+4,high);h2_write32(m,payload+8,10);
            h2_network_session_broadcast(m,s,session,2,23,52,payload);
        } else h2_network_session_cleanup(m,c,session);
        return;
    case 10:if (!force) h2_network_session_cleanup(m,c,session);return;
    default:abort();
    }
}
void h2_network_session_cleanup(h2_memory *m,const h2_session_control_context *c,uint32_t session) {
    if (!h2_read32(m,session+0x741c)) return;
    h2_network_session_request_shutdown(m,c,session,1);
    uint32_t object=h2_read32(m,session+0x78a8);
    if (object) c->cleanup_callback(c->context,h2_read32(m,h2_read32(m,object)+8),object);
    for (uint32_t i=0;i<16;++i)
        if (*h2_ptr(m,session+0x72dc+i*20,1)) h2_network_session_detach_peer(m,session,i);
    h2_write32(m,session+0x7650,h2_read32(m,session+0x7650)+1);
    h2_write32(m,session+0x72d8,UINT32_MAX);
    zero_words(m,session+0x761c,13);
    h2_write32(m,session+0x7654,UINT32_MAX);h2_write32(m,session+0x7658,UINT32_MAX);
    *h2_ptr(m,session+0x78ac,1)=0;*h2_ptr(m,session+0x765c,1)=0;
    h2_network_session_release_registration(m,c->registration,session);
    h2_write32(m,session+0x1c,0);h2_write32(m,session+0x20,0);*h2_ptr(m,session+0x48,1)=0;
    h2_write32(m,session+0x40,UINT32_MAX);
    zero_words(m,session+0x4c,0x925);h2_write32(m,session+0x4c,UINT32_MAX);
    zero_words(m,session+0x4978,0x52c);h2_write32(m,session+0x4978,UINT32_MAX);
    zero_words(m,session+0x7668,0x90);h2_write32(m,session+0x741c,0);
}
