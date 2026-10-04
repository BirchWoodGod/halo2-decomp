#include "halo2/network_session_migration_transition.h"
#include "halo2/network_session_snapshot_reset.h"
#include "halo2/network_session_host_entry.h"
#include "halo2/network_session_migration_send.h"
#include "internal/memory.h"
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
void h2_network_session_begin_migration_transition(h2_memory *m,const h2_session_send_context *s,const h2_observer_tick_context *tick,uint32_t session,uint8_t flag) {
    if(sv(h2_read32(m,session+0x54))<=1) {h2_network_session_begin_host(m,s->clock,session);return;}
    uint32_t state=h2_read32(m,session+0x741c),old_host=h2_read32(m,session+0x40);
    if(state<5 || state>8) {
        h2_network_session_reset_snapshots(m,session,1);
        h2_write32(m,session+0x40,h2_read32(m,session+0x72d8));
    }
    uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : s->clock->ticks(s->clock->context);
    uint32_t mask=UINT32_C(1)<<(h2_read32(m,session+0x72d8)&31);
    for(uint32_t i=0;i<0x1f8;i+=4) h2_write32(m,session+0x7420+i,0);
    h2_write32(m,session+0x7420,(uint32_t)flag<<8);h2_write32(m,session+0x7424,old_host);
    h2_write32(m,session+0x7428,now);h2_write32(m,session+0x742c,mask);
    h2_write32(m,session+0x7430,mask);h2_write32(m,session+0x7434,0);
    h2_write32(m,session+0x741c,8);
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
        uint32_t peer=session+0x72e0+i*20;
        if(!*h2_ptr(m,peer-3,1)) continue;
        uint32_t index=h2_read32(m,peer),observer=h2_read32(m,session+8);
        if(h2_read32(m,observer+index*0x528+0xa8)==1)
            h2_network_observer_request_connection(m,tick,observer,index);
    }
    h2_network_session_send_migration_requests(m,s,session);
}
