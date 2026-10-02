#include "halo2/network_observer_measurement.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t x) {return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *c) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);
}
void h2_network_observer_record_measurement(h2_memory *m,const h2_network_state_operations *c,
    uint32_t observer,uint32_t sample,uint32_t reference,uint32_t comparison) {
    if(sv(reference)>0) {
        uint32_t config=h2_read32(m,observer+16),bits=h2_read32(m,config+0x1ac);
        float factor;memcpy(&factor,&bits,4);
        volatile float a=(float)sv(reference),b=(float)sv(comparison);
        volatile float threshold=a*factor;
        uint8_t high=b>threshold;
        if(h2_read32(m,observer+0x4e10)==UINT32_MAX || *h2_ptr(m,observer+0x4e14,1)!=high) {
            *h2_ptr(m,observer+0x4e14,1)=high;
            uint32_t now=ticks(m,c);h2_write32(m,observer+0x4e10,now);
        }
        uint32_t previous=h2_read32(m,observer+0x4e10),now=ticks(m,c);
        config=h2_read32(m,observer+16);
        if(sv(now-previous)>=sv(h2_read32(m,config+0x1b0))) {
            uint32_t counter=observer+0x4e18+*h2_ptr(m,observer+0x4e14,1)*4u;
            h2_write32(m,counter,h2_read32(m,counter)+1);
            now=ticks(m,c);h2_write32(m,observer+0x4e10,now);
        }
    }
    if(sv(sample)>sv(h2_read32(m,observer+0x4e08))) h2_write32(m,observer+0x4e08,sample);
    uint32_t average=h2_read32(m,observer+0x4e0c);
    if(average!=UINT32_MAX && sv(sample)>sv(average)) {
        uint32_t config=h2_read32(m,observer+16),shift=h2_read32(m,config+0x1b4)&31;
        uint32_t delta=sample-average,adjusted=delta>>shift;
        if(shift && (delta&0x80000000u)) adjusted|=UINT32_MAX<<(32-shift);
        h2_write32(m,observer+0x4e0c,average+adjusted);
    }
}
