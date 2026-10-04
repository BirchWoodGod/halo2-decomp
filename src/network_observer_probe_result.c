#include "halo2/network_observer_probe_result.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *c) {return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);}
static uint32_t measure(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index,uint32_t offset) {
    uint32_t previous=h2_read32(m,observer+0x4f38),entry=observer+0xa8+index*0x528;
    uint32_t elapsed=ticks(m,clock)-previous;
    if(sv(elapsed)<=0) return 0;
    return (uint32_t)(sv(h2_read32(m,entry+offset)*8000u)/sv(elapsed));
}
uint32_t h2_network_observer_measure_rate_a(h2_memory *m,const h2_network_state_operations *c,uint32_t o,uint32_t i) {return measure(m,c,o,i,0x4a8);}
uint32_t h2_network_observer_measure_rate_b(h2_memory *m,const h2_network_state_operations *c,uint32_t o,uint32_t i) {return measure(m,c,o,i,0x4a4);}
void h2_network_observer_probe_failure(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528,count=h2_read32(m,entry+0x4ec)+1;
    h2_write32(m,entry+0x4ec,count);
    uint32_t config=h2_read32(m,observer+16);
    if(sv(count)>=sv(h2_read32(m,config+0x1e4))) {
        h2_write32(m,entry+0x4f0,h2_read32(m,entry+0x4f0)+h2_read32(m,config+0x1e8));return;
    }
    uint32_t divisor=h2_read32(m,config+0x1e0);
    if(!divisor || (count==0x80000000u && divisor==UINT32_MAX)) abort();
    if(sv(count)%sv(divisor)==0) h2_network_observer_reduce_bandwidth(m,clock,observer,index,0);
}
uint32_t h2_network_observer_probe_result(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index) {
    uint32_t previous=h2_read32(m,observer+0x4f38),entry=observer+0xa8+index*0x528;
    uint32_t elapsed=ticks(m,clock)-previous;
    if(sv(elapsed)<sv(h2_read32(m,h2_read32(m,observer+16)+0x1a0))) return 1;
    uint32_t rate=h2_network_observer_measure_rate_a(m,clock,observer,index);
    uint32_t config=h2_read32(m,observer+16),offset=h2_read32(m,config+(*h2_ptr(m,entry+0x48e,1) ? 0x1d8 : 0x1d4));
    uint32_t measured=h2_read32(m,entry+0x4b0),difference=measured-h2_read32(m,entry+0x4b4);
    uint8_t within=sv(difference)<=sv(h2_read32(m,entry+0x4f0)+offset);
    if(sv(measured)>sv(h2_read32(m,entry+0x504)+offset)) return 2;
    if(sv(rate)>sv(h2_read32(m,entry+0x508)) && within) return 0;
    if(!within) h2_network_observer_probe_failure(m,clock,observer,index);
    return 1;
}
