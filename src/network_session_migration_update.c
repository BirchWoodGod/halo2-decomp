#include "halo2/network_session_migration_update.h"
#include "halo2/network_session_migration_transition.h"
#include "halo2/network_session_migration_payload.h"
#include "halo2/network_session_peer_lookup.h"
#include "internal/memory.h"
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
static uint8_t expired(h2_memory *m,const h2_network_state_operations *clock,uint32_t previous,uint32_t limit) {
    uint32_t now=ticks(m,clock);return sv(now-previous)>=sv(h2_read32(m,limit));
}
void h2_network_session_tick_migration(h2_memory *m,const h2_session_control_context *c,const h2_observer_tick_context *tick,uint32_t session,uint32_t payload) {
    const h2_session_send_context *s=c->messages;
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
        if(i==h2_read32(m,session+0x72d8)) continue;
        uint32_t bit=UINT32_C(1)<<(i&31);
        if(h2_read32(m,session+0x74f0)&bit) {
            if(expired(m,s->clock,h2_read32(m,session+0x74f8+i*4),0x4cf4cc)) {
                uint32_t pending=h2_read32(m,session+0x74f0)&~bit;
                uint32_t failed=h2_read32(m,session+0x74f4)|bit;
                h2_write32(m,session+0x74f0,pending);h2_write32(m,session+0x74f4,failed);
            }
            if(h2_read32(m,session+0x74f0)&bit) continue;
        }
        if(!(h2_read32(m,session+0x74f4)&bit) && expired(m,s->clock,h2_read32(m,session+0x7420),0x4cf4cc))
            h2_write32(m,session+0x74f4,h2_read32(m,session+0x74f4)|bit);
    }
    uint32_t candidate=h2_read32(m,session+0x742c);
    if(candidate!=h2_read32(m,session+0x72d8)) {
        if(h2_read32(m,session+0x74f4)&(UINT32_C(1)<<(candidate&31))) {
            uint32_t local=h2_network_session_build_migration_payload(m,session,session+0x7430);
            h2_write32(m,session+0x742c,local);h2_write32(m,session+0x7428,ticks(m,s->clock));
        }
    } else {
        uint32_t failed=0,missing=0;
        for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
            if(h2_read32(m,session+0x74f4)&(UINT32_C(1)<<(i&31))) ++failed;
            else {
                uint32_t index=h2_network_session_find_peer_identity(m,session+0x7430,session+0x58+i*0x10c);
                if(index==UINT32_MAX || !(h2_read32(m,session+0x74ec)&(UINT32_C(1)<<(index&31)))) ++missing;
            }
        }
        if((!failed || (expired(m,s->clock,h2_read32(m,session+0x7420),0x4cf4cc) && expired(m,s->clock,h2_read32(m,session+0x7428),0x4cf4d0))) && !missing)
            h2_network_session_begin_migration_transition(m,s,tick,session,1);
    }
    if(h2_read32(m,session+0x741c)!=9) return;
    uint32_t previous=h2_read32(m,session+0x7424);
    uint8_t send=1;
    if(previous && !expired(m,s->clock,previous,0x4cf4d4)) {
        previous=h2_read32(m,session+0x7424);
        if(sv(h2_read32(m,session+0x7428)-previous)<=0) send=0;
        else if(sv(ticks(m,s->clock)-previous)<500) send=0;
    }
    if(send) {
        uint32_t low=h2_read32(m,session+0x1c);
        for(uint32_t i=0;i<200;i+=4) h2_write32(m,payload+i,0);
        h2_write32(m,payload+4,h2_read32(m,session+0x20));h2_write32(m,payload,low);
        for(uint32_t i=0;i<192;i+=4) h2_write32(m,payload+8+i,h2_read32(m,session+0x7430+i));
        for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
            uint32_t peer=session+0x72e0+i*20;
            if(*h2_ptr(m,peer-3,1)) h2_network_observer_send(m,s->clock,s->send,s->codec,s->resolution,s->queue,
                h2_read32(m,session+8),h2_read32(m,peer),h2_read32(m,session+0x10),1,22,200,payload,
                s->local,s->reliable,s->packet,s->address_workspace);
        }
        h2_write32(m,session+0x7424,ticks(m,s->clock));
    }
    if(expired(m,s->clock,h2_read32(m,session+0x7420),0x4cf4c8)) h2_network_session_cleanup(m,c,session);
}
