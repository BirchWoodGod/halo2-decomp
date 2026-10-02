#include "halo2/network_observer_timeout.h"
#include "halo2/network_observer_retry.h"
#include "internal/memory.h"
static int64_t signed32(uint32_t v) {
    return v & 0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;
}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_observer_check_timeout(h2_memory *m,const h2_observer_tick_context *c,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528;
    if (!h2_read32(m,entry)) return;
    uint32_t id=h2_read32(m,entry+12);
    if (id!=UINT32_MAX) {
        uint32_t connection=h2_read32(m,0x4d87d4)+id*0xf8;
        if (h2_read32(m,connection+0x54)==5) {
            uint32_t previous=h2_read32(m,connection+0x98);
            uint32_t now=ticks(m,c->clock);
            uint32_t config=h2_read32(m,observer+16);
            if (signed32(now-previous)<signed32(h2_read32(m,config+0x74))) {
                uint32_t idle=h2_network_elapsed(m,c->clock,h2_read32(m,entry+0x94));
                uint32_t last=0;
                if (signed32(h2_read32(m,connection+0x54))>2) last=h2_read32(m,connection+0xc8);
                uint32_t elapsed=h2_network_elapsed(m,c->clock,last);
                config=h2_read32(m,observer+16);
                if (signed32(idle)<signed32(h2_read32(m,config+0x80)) ||
                    signed32(elapsed)<signed32(h2_read32(m,config+0x84))) return;
                h2_network_connection_close(m,c->clock,c->send,c->codec,c->connections,
                    connection,16,c->detach16,c->packet,c->workspace28);
                return;
            }
        }
    }
    uint32_t now=ticks(m,c->clock);
    h2_write32(m,entry+0x94,now);
}
