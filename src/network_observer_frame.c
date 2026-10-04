#include "halo2/network_observer_frame.h"
#include "halo2/network_observer_retry.h"
#include "halo2/network_observer_timeout.h"
#include "halo2/network_observer_bandwidth.h"
#include "halo2/network_observer_route_mode.h"
#include "internal/memory.h"

void h2_network_observer_frame(h2_memory *m,const h2_observer_frame_context *c,uint32_t observer) {
    const h2_observer_tick_context *t=c->tick;
    for(uint32_t index=0;index<15;++index) {
        uint32_t entry=observer+0xa8+index*0x528;
        if(!h2_read32(m,entry)) continue;
        if(!*h2_ptr(m,entry+9,1) &&
           h2_network_observer_retry_allowed(m,t->clock,t->send,t->codec,t->connections,
               observer,index,14,t->detach16,t->packet,t->workspace28))
            h2_network_observer_release_slot(m,t->clock,t->send,t->codec,t->connections,
                t->registration,t->storage,c->async->tasks,observer,index,
                t->detach16,t->packet,t->storage8,t->workspace28);
        if(!h2_read32(m,entry)) continue;
        /* The original only rechecks state here, not between these calls. */
        h2_network_observer_refresh_address(m,t->query,t->clock,t->send,t->codec,
            t->connections,t->registration,t->events,observer,index,t->query4,
            t->detach16,t->packet,t->workspace28);
        h2_network_observer_update_slot(m,t->clock,t->send,t->codec,t->connections,
            t->registration,t->events,observer,index,t->detach16,t->packet,t->workspace28);
        h2_network_observer_tick(m,t,observer,index);
        h2_network_observer_check_timeout(m,t,observer,index);
        h2_network_observer_async(m,c->async,observer,index,c->records60);
    }
    h2_network_observer_update_bandwidth(m,t->clock,observer);
    h2_network_observer_control_bandwidth(m,t->clock,c->control,observer,c->control152);
    h2_network_observer_update_route_mode(m,observer);
}
