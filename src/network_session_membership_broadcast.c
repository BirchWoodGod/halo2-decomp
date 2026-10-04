#include "halo2/network_session_membership_broadcast.h"
#include "halo2/network_membership_snapshot.h"
#include "halo2/network_observer_message_gate.h"
#include "internal/memory.h"
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
void h2_network_session_broadcast_membership(h2_memory *m,const h2_session_send_context *c,uint32_t session,uint32_t full,uint32_t delta) {
    uint32_t full_mask=0,delta_mask=0;
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
        uint32_t peer=session+0x72e0+i*20;
        if(!*h2_ptr(m,peer-3,1) || *h2_ptr(m,peer-1,1)) continue;
        uint32_t index=h2_read32(m,peer),observer=h2_read32(m,session+8);
        if(h2_read32(m,observer+index*0x528+0xa8)!=7) continue;
        uint32_t revision=h2_read32(m,peer+4);
        if(revision==h2_read32(m,session+0x4c)) continue;
        if(h2_network_observer_message_deferred(m,observer,index,25)) {
            h2_network_observer_defer_message(m,observer,index,25);
        } else if(h2_read32(m,session+0x741c)!=8) {
            uint32_t bit=UINT32_C(1)<<(i&31);
            if(revision!=UINT32_MAX && revision==h2_read32(m,session+0x24e0)) delta_mask|=bit;
            else full_mask|=bit;
        }
    }
    if(full_mask) h2_network_membership_snapshot(m,session,session+0x4c,0,full);
    if(delta_mask) h2_network_membership_snapshot(m,session,session+0x4c,session+0x24e0,delta);
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
        uint32_t bit=UINT32_C(1)<<(i&31),message;
        if(delta_mask&bit) message=delta;
        else if(full_mask&bit) message=full;
        else continue;
        uint32_t peer=session+0x72dd+i*20;
        h2_write32(m,peer+7,h2_read32(m,session+0x4c));
        if(*h2_ptr(m,peer,1)) h2_network_observer_send(m,c->clock,c->send,c->codec,c->resolution,c->queue,h2_read32(m,session+8),h2_read32(m,peer+3),h2_read32(m,session+0x10),0,25,0x489c,message,c->local,c->reliable,c->packet,c->address_workspace);
    }
    for(uint32_t off=0;off<0x2494;off+=4) h2_write32(m,session+0x24e0+off,h2_read32(m,session+0x4c+off));
}
