#include "halo2/network_observer_probe.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static float rf(h2_memory *m,uint32_t p) {uint32_t bits=h2_read32(m,p);float f;memcpy(&f,&bits,4);return f;}
void h2_network_observer_reset_probe(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528;
    if(!h2_read32(m,entry+0x4dc)) return;
    uint8_t overridden=*h2_ptr(m,0x510548,1);
    h2_write32(m,entry+0x4dc,0);
    uint32_t now=overridden ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,entry+0x4e0,now);
}
void h2_network_observer_restore_probe(h2_memory *m,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528;
    if(!*h2_ptr(m,entry+0x4f4,1)) return;
    uint32_t burst=h2_read32(m,entry+0x4fc);float rate=rf(m,entry+0x500);
    uint32_t budget=h2_read32(m,entry+0x4f8);
    h2_network_observer_apply_rate(m,observer,index,rate,budget,burst);
    *h2_ptr(m,entry+0x4f4,1)=0;h2_write32(m,entry+0x4dc,1);
}
float h2_network_observer_probe_priority(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528;
    if(h2_read32(m,entry+0x4dc)!=1) return 0.0f;
    uint32_t previous=h2_read32(m,entry+0x4e8);float score;
    if(previous!=UINT32_MAX) {
        uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
        uint32_t config=h2_read32(m,observer+16);
        volatile float converted=(float)sv((now-previous)*h2_read32(m,config+0x1cc));
        score=converted;
        float maximum=rf(m,config+0x1c8);if(score>maximum) score=maximum;
    } else score=rf(m,h2_read32(m,observer+16)+0x1c8);
    uint32_t config=h2_read32(m,observer+16);
    volatile float budget=(float)sv(h2_read32(m,entry+0x494));
    volatile float penalty=budget*rf(m,config+0x1d0);
    volatile float result=score-penalty;return result;
}
