#include "halo2/network_session_migration_send.h"
#include "internal/memory.h"
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
void h2_network_session_send_migration_requests(h2_memory *m,const h2_session_send_context *s,uint32_t session) {
    uint32_t mask=(UINT32_C(1)<<(h2_read32(m,session+0x7424)&31)) |
        h2_read32(m,session+0x7434) | h2_read32(m,session+0x7430);
    uint8_t include_host=mask==((UINT32_C(1)<<(h2_read32(m,session+0x54)&31))-1);
    if(!include_host) {
        uint8_t cached=*h2_ptr(m,0x510548,1);
        uint32_t previous=h2_read32(m,session+0x7428);
        uint32_t now=cached ? h2_read32(m,0x51054c) : s->clock->ticks(s->clock->context);
        include_host=sv(now-previous)>=sv(h2_read32(m,0x4cf4c4));
    }
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
        if(i==h2_read32(m,session+0x7424) && !include_host) continue;
        uint32_t bit=UINT32_C(1)<<(i&31),peer=session+0x72e0+i*20;
        if(h2_read32(m,session+0x742c)&bit || !*h2_ptr(m,peer-3,1)) continue;
        uint32_t index=h2_read32(m,peer),observer=h2_read32(m,session+8);
        if(h2_read32(m,observer+index*0x528+0xa8)!=7) continue;
        h2_write32(m,s->message,h2_read32(m,session+0x1c));
        h2_write32(m,s->message+4,h2_read32(m,session+0x20));
        h2_network_observer_send(m,s->clock,s->send,s->codec,s->resolution,s->queue,
            observer,index,h2_read32(m,session+0x10),0,18,8,s->message,
            s->local,s->reliable,s->packet,s->address_workspace);
        h2_write32(m,session+0x742c,h2_read32(m,session+0x742c)|bit);
    }
}
