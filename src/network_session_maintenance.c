#include "halo2/network_session_maintenance.h"
#include "halo2/network_session.h"
#include "internal/memory.h"
static int64_t signed_value(uint32_t n) {
    return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;
}
void h2_network_session_maintain_connections(h2_memory *m,const h2_observer_tick_context *c,uint32_t session) {
    if(!h2_read32(m,session+0x741c)) return;
    for(uint32_t i=0;signed_value(i)<signed_value(h2_read32(m,session+0x54));++i) {
        uint32_t peer=session+0x72e0+i*20;
        if(!*h2_ptr(m,peer-3,1)) continue;
        uint32_t state=h2_read32(m,session+0x741c);
        if(state<5 || state>8) {
            if(h2_network_session_shutdown_guard(m,session) || h2_read32(m,session+0x4c)==UINT32_MAX) continue;
            if((state==1 || (signed_value(state)>2 && signed_value(state)<=8)) && !*h2_ptr(m,session+0x7c+i*0x10c,1)) continue;
        }
        uint32_t index=h2_read32(m,peer),observer=h2_read32(m,session+8);
        if(h2_read32(m,observer+0xa8+index*0x528)!=1)
            h2_network_observer_request_connection(m,c,observer,index);
    }
}
