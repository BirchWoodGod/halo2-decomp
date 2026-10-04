#include "halo2/network_observer_cycle.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
void h2_network_observer_finish_cycle(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer) {
    uint32_t timestamp=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    if(!*h2_ptr(m,0x510548,1)) (void)clock->ticks(clock->context);
    for(uint32_t i=0;i<15;++i) {
        uint32_t e=observer+0xa8+i*0x528;
        if(!h2_read32(m,e) || !*h2_ptr(m,e+0x48c,1)) continue;
        uint32_t measured=h2_network_observer_measure_rate_b(m,clock,observer,i);
        (void)h2_network_observer_measure_rate_a(m,clock,observer,i);
        uint32_t metric=h2_read32(m,e+0x4b0);
        if(sv(measured)>0) {
            *h2_ptr(m,e+0x50c,1)|=*h2_ptr(m,e+0x4a1,1);
            *h2_ptr(m,e+0x50d,1)|=*h2_ptr(m,e+0x4a0,1);
            *h2_ptr(m,e+0x50e,1)|=*h2_ptr(m,e+0x4a2,1);
        }
        if(!*h2_ptr(m,e+0x50c,1)&&!*h2_ptr(m,e+0x50d,1)&&!*h2_ptr(m,e+0x50e,1)) {
            h2_write32(m,e+0x51c,h2_read32(m,e+0x51c)+1);h2_write32(m,e+0x518,0);
        } else {h2_write32(m,e+0x518,h2_read32(m,e+0x518)+1);h2_write32(m,e+0x51c,0);}
        if(sv(metric)<sv(h2_read32(m,e+0x4f0))) {h2_write32(m,e+0x4f0,metric);h2_write32(m,e+0x4ec,0);}
        h2_write32(m,e+0x4a8,0);h2_write32(m,e+0x4a4,0);
        *h2_ptr(m,e+0x4a1,1)=0;*h2_ptr(m,e+0x4a2,1)=0;
    }
    h2_write32(m,observer+0x4f38,timestamp);
}
