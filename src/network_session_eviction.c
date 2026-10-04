#include "halo2/network_session_eviction.h"
#include "halo2/network_session_removal.h"
#include "internal/memory.h"
static void send_notice(h2_memory *m,const h2_session_send_context *c,uint32_t session,uint32_t peer,uint8_t unreliable,uint32_t message) {
    h2_network_observer_send(m,c->clock,c->send,c->codec,c->resolution,c->queue,h2_read32(m,session+8),h2_read32(m,peer+4),h2_read32(m,session+0x10),unreliable,13,8,message,c->local,c->reliable,c->packet,c->address_workspace);
}
void h2_network_session_evict_peer(h2_memory *m,const h2_session_send_context *c,uint32_t session,uint32_t index,uint32_t message,uint32_t removal) {
    uint32_t high=h2_read32(m,session+0x20),low=h2_read32(m,session+0x1c);
    uint32_t peer=session+index*20+0x72dc;
    h2_write32(m,message,low);h2_write32(m,message+4,high);
    if(*h2_ptr(m,peer+1,1)) {
        uint32_t observer=h2_read32(m,session+8),slot=h2_read32(m,peer+4);
        if(h2_read32(m,observer+slot*0x528+0xa8)==7) send_notice(m,c,session,peer,0,message);
        send_notice(m,c,session,peer,1,message);
    }
    h2_network_session_remove_peer(m,session,index,removal);
}
