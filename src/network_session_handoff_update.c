/* Draft recovery: see header for validation status. */
#include "halo2/network_session_handoff_update.h"
#include "halo2/network_session_handoff_remove.h"
#include "halo2/network_session_host_entry.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_session_tick_handoff(h2_memory *m,const h2_session_control_context *c,const h2_candidate_rank_math *math,uint32_t session,uint32_t offer,uint32_t confirmation) {
    const h2_session_send_context *s=c->messages;
    uint8_t become_host=0;
    if(h2_read32(m,session+0x742c)==UINT32_MAX) {
        uint32_t candidate=UINT32_MAX,eligible=0;
        if(!h2_read32(m,session+0x7424)) become_host=1;
        else {
            if(!*h2_ptr(m,session+0x7420,1)) candidate=h2_read32(m,session+0x72d8);
            for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
                uint32_t bit=UINT32_C(1)<<(i&31),peer=session+0x72e8+i*20;
                if(!(h2_read32(m,session+0x7424)&bit) || h2_read32(m,peer-4)!=h2_read32(m,session+0x4c) || h2_read32(m,peer)!=h2_read32(m,session+0x4978)) continue;
                if(!*h2_ptr(m,session+0x7420,1) && h2_read32(m,session+0xf4+i*0x10c)!=((UINT32_C(1)<<(h2_read32(m,session+0x54)&31))-1)) continue;
                eligible|=bit;
                if(candidate==UINT32_MAX || h2_network_session_candidate_preferred(m,math,session+0x58,i,candidate,h2_read32(m,session+0x54))) candidate=i;
            }
            if(candidate==h2_read32(m,session+0x72d8)) {
                if(eligible==h2_read32(m,session+0x7424)) become_host=1;
            } else if(candidate!=UINT32_MAX) {
                uint32_t mask=h2_read32(m,session+0x7424);
                h2_write32(m,session+0x742c,candidate);
                h2_write32(m,session+0x7424,mask&~(UINT32_C(1)<<(candidate&31)));
            }
        }
    }
    uint32_t selected=h2_read32(m,session+0x742c);
    if(selected==UINT32_MAX) {
        uint32_t previous=h2_read32(m,session+0x7428),now=ticks(m,s->clock);
        if(sv(now-previous)>=sv(h2_read32(m,0x4cf4b8))) become_host=1;
    } else {
        if(!*h2_ptr(m,session+0x7430,1)) {
            memset(h2_ptr(m,offer,46),0,46);
            uint32_t low=h2_read32(m,session+0x1c),high=h2_read32(m,session+0x20);
            h2_write32(m,offer,low);h2_write32(m,offer+4,high);
            *h2_ptr(m,offer+44,1)=(uint8_t)selected;*h2_ptr(m,offer+45,1)=(uint8_t)(selected>>8);
            for(uint32_t i=0;i<36;i+=4) h2_write32(m,offer+8+i,h2_read32(m,session+selected*0x10c+0x58+i));
            h2_network_session_broadcast(m,s,session,0,15,46,offer);
            uint8_t cached=*h2_ptr(m,0x510548,1);*h2_ptr(m,session+0x7430,1)=1;
            uint32_t now=cached ? h2_read32(m,0x51054c) : s->clock->ticks(s->clock->context);
            h2_write32(m,session+0x7434,now);
            h2_write32(m,session+0x7438,UINT32_C(1)<<(h2_read32(m,session+0x72d8)&31));
        }
        if(*h2_ptr(m,session+0x7430,1) && !*h2_ptr(m,session+0x743c,1)) {
            uint32_t previous=h2_read32(m,session+0x7434),now=ticks(m,s->clock);
            uint32_t ack=h2_read32(m,session+0x7438);
            uint8_t confirm=ack==((UINT32_C(1)<<(h2_read32(m,session+0x54)&31))-1);
            if(!confirm && sv(now-previous)>=sv(h2_read32(m,0x4cf4b4))) {
                uint32_t peer=h2_read32(m,session+0x742c);
                if(ack&(UINT32_C(1)<<(peer&31))) confirm=1;
                else h2_network_session_remove_handoff_candidate(m,s->clock,session,peer);
            }
            if(confirm) {
                uint32_t peer=session+h2_read32(m,session+0x742c)*20+0x72dc;
                uint32_t low=h2_read32(m,session+0x1c),high=h2_read32(m,session+0x20);
                h2_write32(m,confirmation,low);h2_write32(m,confirmation+4,high);
                if(*h2_ptr(m,peer+1,1)) h2_network_observer_send(m,s->clock,s->send,s->codec,s->resolution,s->queue,h2_read32(m,session+8),h2_read32(m,peer+4),h2_read32(m,session+0x10),0,17,8,confirmation,s->local,s->reliable,s->packet,s->address_workspace);
                uint8_t cached=*h2_ptr(m,0x510548,1);*h2_ptr(m,session+0x743c,1)=1;
                now=cached ? h2_read32(m,0x51054c) : s->clock->ticks(s->clock->context);
                uint32_t peer_index=h2_read32(m,session+0x742c);
                h2_write32(m,session+0x7440,now);h2_write32(m,session+0x44,peer_index);
            }
        }
        if(*h2_ptr(m,session+0x743c,1)) {
            uint32_t previous=h2_read32(m,session+0x7440),now=ticks(m,s->clock);
            if(sv(now-previous)>=sv(h2_read32(m,0x4cf4bc))) h2_network_session_remove_handoff_candidate(m,s->clock,session,h2_read32(m,session+0x742c));
        }
    }
    if(become_host) {
        uint8_t shutdown=*h2_ptr(m,session+0x7420,1);
        h2_network_session_begin_host(m,s->clock,session);
        if(shutdown) h2_network_session_request_shutdown(m,c,session,1);
    }
}
