#include "halo2/network_observer_reduce.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t maximum(uint32_t a,uint32_t b) {return sv(a)>sv(b) ? a : b;}
static uint32_t minimum(uint32_t a,uint32_t b) {return sv(a)>sv(b) ? b : a;}
static float rf(h2_memory *m,uint32_t p) {uint32_t b=h2_read32(m,p);float f;memcpy(&f,&b,4);return f;}
static void wf(h2_memory *m,uint32_t p,float f) {uint32_t b;memcpy(&b,&f,4);h2_write32(m,p,b);}
static uint32_t convert(float f,int round) {double v=round ? nearbyint((double)f) : trunc((double)f);return !isfinite(v)||v < -2147483648.0||v > 2147483647.0 ? 0x80000000u : (uint32_t)(int64_t)v;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *c) {return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);}
void h2_network_observer_reduce_peer(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528,previous=h2_read32(m,observer+0x4f34);
    if(previous!=UINT32_MAX) {
        uint32_t elapsed=ticks(m,clock)-previous;
        if(elapsed!=UINT32_MAX && sv(elapsed)<sv(h2_read32(m,h2_read32(m,observer+16)+0x1bc))) return;
    }
    uint8_t original_kind=*h2_ptr(m,entry+0x48e,1),kind=original_kind;
    uint32_t threshold=maximum(h2_read32(m,entry+0x514),h2_read32(m,entry+0x510))+h2_read32(m,h2_read32(m,observer+16)+0x1b8),selected=UINT32_MAX;
    for(uint32_t i=0;i<15;i++) {
        uint32_t peer=observer+0xa8+i*0x528;
        if(!h2_read32(m,peer) || !*h2_ptr(m,peer+0x48c,1)) continue;
        uint32_t metric=maximum(h2_read32(m,peer+0x514),h2_read32(m,peer+0x510));
        if(sv(metric)>sv(threshold)) {threshold=metric;selected=i;kind=*h2_ptr(m,peer+0x48e,1);}
    }
    if(selected!=UINT32_MAX && (!kind || original_kind)) {
        h2_network_observer_reduce_bandwidth(m,clock,observer,selected,0);
        h2_write32(m,observer+0x4f34,ticks(m,clock));
    }
}
void h2_network_observer_reduce_bandwidth(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index,uint8_t propagate) {
    uint32_t entry=observer+0xa8+index*0x528;
    if(propagate) h2_network_observer_reduce_peer(m,clock,observer,index);
    if(*h2_ptr(m,entry+0x4f4,1)) h2_network_observer_restore_probe(m,observer,index);
    uint8_t pending=*h2_ptr(m,entry+0x4c0,1);h2_write32(m,entry+0x4ec,0);
    uint32_t old_budget=h2_read32(m,entry+(pending ? 0x4cc : 0x494)),old_burst=h2_read32(m,entry+(pending ? 0x4d0 : 0x498));
    uint32_t config=h2_read32(m,observer+16);
    volatile float value=(float)sv(old_budget);volatile float product=value*rf(m,config+0x198);
    config=h2_read32(m,observer+16);
    uint32_t decrease=minimum(convert(product,1),h2_read32(m,config+0x194));
    uint32_t budget=maximum(old_budget-decrease,h2_read32(m,config+0x14c));
    uint32_t numerator=budget*old_burst;
    if(!old_budget || (numerator==0x80000000u && old_budget==UINT32_MAX)) abort();
    uint32_t burst=maximum((uint32_t)(sv(numerator)/sv(old_budget)),h2_read32(m,config+0xe0));
    float rate=h2_network_observer_select_rate(m,observer,budget,*h2_ptr(m,entry+0x48e,1),*h2_ptr(m,entry+0x490,1));
    if(*h2_ptr(m,entry+0x4c0,1)) {
        uint32_t limited_budget=minimum(budget,h2_read32(m,entry+0x494)),limited_burst=minimum(burst,h2_read32(m,entry+0x498));
        float current=rf(m,entry+0x49c),selected=current>rate ? rate : current;
        volatile float integer_rate=(float)sv(convert(selected,0));
        h2_network_observer_apply_rate(m,observer,index,integer_rate,limited_budget,limited_burst);
        h2_write32(m,entry+0x4cc,budget);h2_write32(m,entry+0x4d0,burst);wf(m,entry+0x4d4,rate);
    } else h2_network_observer_apply_rate(m,observer,index,rate,budget,burst);
    *h2_ptr(m,observer+0x4f3c,1)=1;*h2_ptr(m,observer+0x4f3d,1)=1;
    if(propagate) *h2_ptr(m,observer+0x4f3e,1)=1;
    h2_network_observer_reset_probe(m,clock,observer,index);
}
