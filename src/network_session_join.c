#include "halo2/network_session_join.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_session_tick_join(h2_memory *m,const h2_network_query_platform *query,
    const h2_session_control_context *c,uint32_t session,uint32_t confirmation,
    uint32_t retry_payload,uint32_t query_scratch) {
    const h2_session_send_context *s=c->messages;
    uint32_t result=h2_network_observer_query(m,query,h2_read32(m,session+8),h2_read32(m,session+0x7420),query_scratch);
    uint32_t previous,now,limit;
    if(result!=2) {
        previous=h2_read32(m,session+0x7608);now=ticks(m,s->clock);limit=h2_read32(m,0x4cf498);
    } else {
        if(!h2_read32(m,session+0x760c)) h2_write32(m,session+0x760c,ticks(m,s->clock));
        if(h2_read32(m,session+0x4c)!=UINT32_MAX && h2_read32(m,session+0x4978)!=UINT32_MAX) {
            h2_network_session_begin_connected(m,c,session);
            uint32_t low=h2_read32(m,session+0x1c),high=h2_read32(m,session+0x20);
            h2_write32(m,confirmation,low);h2_write32(m,confirmation+4,high);
            uint32_t peer=session+h2_read32(m,session+0x50)*20+0x72dc;
            if(*h2_ptr(m,peer+1,1))
                h2_network_observer_send(m,s->clock,s->send,s->codec,s->resolution,s->queue,
                    h2_read32(m,session+8),h2_read32(m,peer+4),h2_read32(m,session+0x10),0,
                    21,8,confirmation,s->local,s->reliable,s->packet,s->address_workspace);
            goto retry;
        }
        previous=h2_read32(m,session+0x760c);now=ticks(m,s->clock);limit=h2_read32(m,0x4cf49c);
    }
    if(sv(now-previous)>sv(limit)) {
        h2_network_session_request_shutdown(m,c,session,0);return;
    }
retry:
    if(h2_read32(m,session+0x741c)==1)
        h2_network_session_resend_join(m,query,s->clock,s->send,s->codec,session,retry_payload,
            query_scratch,s->packet,s->address_workspace);
}
