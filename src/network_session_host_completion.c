#include "halo2/network_session_host_completion.h"
#include "halo2/network_session_migration_send.h"
#include "halo2/network_session_host_entry.h"
#include "halo2/network_session_eviction.h"
#include "halo2/network_session_membership_broadcast.h"
#include "halo2/network_session_parameters_broadcast.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t mask(h2_memory *m,uint32_t s) {return (UINT32_C(1)<<(h2_read32(m,s+0x54)&31))-1;}
void h2_network_session_complete_host(h2_memory *m,const h2_session_control_context *c,uint32_t s,uint32_t eviction,uint32_t removal,uint32_t mf,uint32_t md,uint32_t pf,uint32_t pd) {
    const h2_session_send_context *send=c->messages;
    h2_network_session_send_migration_requests(m,send,s);
    if((h2_read32(m,s+0x7430)|h2_read32(m,s+0x7434))!=mask(m,s)) {
        uint32_t previous=h2_read32(m,s+0x7428);
        uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : send->clock->ticks(send->clock->context);
        if(sv(now-previous)<sv(h2_read32(m,0x4cf4c0))) return;
    }
    uint32_t evict=(mask(m,s)&~h2_read32(m,s+0x7430))|h2_read32(m,s+0x7434);
    uint8_t shutdown=*h2_ptr(m,s+0x7420,1),handoff=*h2_ptr(m,s+0x7421,1);
    h2_network_session_begin_host(m,send->clock,s);
    if(evict) for(uint32_t i=h2_read32(m,s+0x54)-1;!(i&UINT32_C(0x80000000));--i)
        if(i!=h2_read32(m,s+0x72d8) && (evict&(UINT32_C(1)<<(i&31))))
            h2_network_session_evict_peer(m,send,s,i,eviction,removal);
    h2_network_session_broadcast_membership(m,send,s,mf,md);
    h2_network_session_broadcast_parameters(m,send,s,pf,pd);
    if(shutdown) h2_network_session_request_shutdown(m,c,s,0);
    else if(handoff) h2_network_session_begin_handoff(m,c,s,0,UINT32_MAX);
}
