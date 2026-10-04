#include "halo2/network_session_update.h"
#include "halo2/network_session_join.h"
#include "halo2/network_session_timeouts.h"
#include "halo2/network_session_handoff_update.h"
#include "halo2/network_session_host_completion.h"
#include "halo2/network_session_migration_update.h"
#include "halo2/network_session_disconnect.h"
#include "halo2/network_session_status.h"
#include "halo2/network_session_maintenance.h"
#include "halo2/network_session_reservation_expiry.h"
#include "halo2/network_session_eviction.h"
#include "halo2/network_session_membership_broadcast.h"
#include "halo2/network_session_parameters_broadcast.h"
#include "internal/memory.h"
static int64_t signed32(uint32_t n) {
    return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;
}
static int host_state(uint32_t state) {return state>=5 && state<=8;}
void h2_network_session_update(h2_memory *m,const h2_session_control_context *c,
    const h2_observer_tick_context *o,const h2_candidate_rank_math *math,
    uint32_t s,const h2_session_update_scratch *w) {
    uint32_t state=h2_read32(m,s+0x741c);
    if(!state || state==10) return;
    switch(state) {
    case 1:h2_network_session_tick_join(m,o->query,c,s,w->confirmation,w->retry,w->query);break;
    case 2:h2_network_session_tick_join_abort(m,c,s);break;
    case 4:h2_network_session_tick_leave(m,c,s);break;
    case 6:h2_network_session_cleanup(m,c,s);break;
    case 7:h2_network_session_tick_handoff(m,c,math,s,w->offer,w->handoff_confirmation);break;
    case 8:h2_network_session_complete_host(m,c,s,w->eviction,w->removal,
        w->membership_full,w->membership_delta,w->parameters_full,w->parameters_delta);break;
    case 9:h2_network_session_tick_migration(m,c,o,s,w->migration_payload);break;
    default:break;
    }
    state=h2_read32(m,s+0x741c);
    if(host_state(state)) {
        h2_network_session_expire_reservations(m,c->messages->clock,s);
        state=h2_read32(m,s+0x741c);
        if(state!=7 && state!=6 && state!=8) {
            for(uint32_t i=0;signed32(i)<signed32(h2_read32(m,s+0x54));++i) {
                uint32_t peer=s+0x72e0+i*20;
                if(*h2_ptr(m,peer-3,1)) {
                    uint32_t entry=h2_read32(m,s+8)+h2_read32(m,peer)*0x528+0xa8;
                    if(h2_read32(m,entry)==1)
                        h2_network_session_evict_peer(m,c->messages,s,i,w->eviction,w->removal);
                }
            }
        }
    } else if(state>2 && state<=8) {
        uint32_t peer=h2_read32(m,s+0x40),observer=h2_read32(m,s+8);
        uint32_t index=h2_read32(m,s+0x72e0+peer*20);
        if(h2_read32(m,observer+index*0x528+0xa8)==1)
            h2_network_session_handle_disconnect(m,c,o->connections,s,w->close,w->migration);
        state=h2_read32(m,s+0x741c);
        if(state>2 && state<=8) h2_network_session_send_status_request(m,c,s);
    }
    h2_network_session_maintain_connections(m,o,s);
    if(host_state(h2_read32(m,s+0x741c))) {
        h2_network_session_broadcast_membership(m,c->messages,s,w->membership_full,w->membership_delta);
        h2_network_session_broadcast_parameters(m,c->messages,s,w->parameters_full,w->parameters_delta);
    }
}
