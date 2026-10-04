#include "halo2/network_observer_probe_start.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static float cv(uint32_t v) {volatile float f=(float)sv(v);return f;}
static float rf(h2_memory *m,uint32_t p) {uint32_t b=h2_read32(m,p);float f;memcpy(&f,&b,4);return f;}
static uint32_t minimum(uint32_t a,uint32_t b) {return sv(a)>sv(b) ? b : a;}
static uint32_t convert(float f,int round) {double v=round ? nearbyint((double)f) : trunc((double)f);return !isfinite(v)||v < -2147483648.0||v > 2147483647.0 ? 0x80000000u : (uint32_t)(int64_t)v;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *c) {return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);}
uint8_t h2_network_observer_start_probe(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index,uint32_t exhausted) {
    uint32_t entry=observer+0xa8+index*0x528,config=h2_read32(m,observer+16);
    volatile float product=cv(h2_read32(m,entry+0x494))*rf(m,config+0x190);
    config=h2_read32(m,observer+16);
    uint32_t increase=minimum(convert(product,1),h2_read32(m,config+0x18c));
    uint32_t maximum=h2_read32(m,config+0x150),old_budget=h2_read32(m,entry+0x494);
    uint32_t proposed_budget=minimum(increase+old_budget,maximum);
    uint8_t grow_budget=sv(proposed_budget)>sv(old_budget);
    float old_rate=rf(m,entry+0x49c);volatile float extra=0.0f;
    if(old_rate>0.0f) {volatile float denominator=old_rate*rf(m,0x45dc18);extra=cv(old_budget)/denominator;}
    uint32_t old_burst=h2_read32(m,entry+0x498),proposed_burst=convert(extra,0)+old_burst;
    uint8_t grow_burst=sv(proposed_burst)>sv(old_burst);
    old_rate=rf(m,entry+0x49c);
    float proposed_rate=h2_network_observer_next_rate(m,observer,old_rate,*h2_ptr(m,entry+0x490,1));
    volatile float delta=proposed_rate-old_rate;
    uint8_t grow_rate=delta>rf(m,0x45dbdc);
    uint32_t previous=h2_read32(m,observer+0x4f38),elapsed=ticks(m,clock)-previous;
    if(!grow_budget && !grow_burst && !grow_rate) {*h2_ptr(m,exhausted,1)=1;return 0;}
    uint8_t started=0;
    config=h2_read32(m,observer+16);
    if(sv(elapsed)>=sv(h2_read32(m,config+0x1a0))) {
        if(sv(h2_read32(m,observer+0x4f40))>=sv(h2_read32(m,observer+0x4f44))) {
            if(*h2_ptr(m,config+0x144,1)) {
                (void)h2_network_observer_measure_rate_b(m,clock,observer,index);
                (void)h2_network_observer_measure_rate_a(m,clock,observer,index);
            }
        } else {
            float rate=rf(m,entry+0x49c);
            uint32_t budget=h2_read32(m,entry+0x494),burst=h2_read32(m,entry+0x498);
            if(grow_burst && *h2_ptr(m,entry+0x4a2,1)) {burst=proposed_burst;started=1;}
            else if(grow_budget && *h2_ptr(m,entry+0x4a1,1)) {budget=proposed_budget;started=1;}
            else if(grow_rate && *h2_ptr(m,entry+0x4a0,1)) {rate=proposed_rate;started=1;}
            if(rate>rf(m,entry+0x49c)) {
                uint32_t required=h2_network_observer_rate_budget(m,observer,*h2_ptr(m,entry+0x48e,1),rate);
                float required_float=cv(required),budget_float=cv(budget);
                budget=convert(budget_float>required_float ? budget_float : required_float,0);
            }
            uint32_t current_budget=h2_read32(m,entry+0x494);
            if(sv(budget)>sv(current_budget)) {
                uint32_t numerator=h2_read32(m,entry+0x498)*budget;
                if(!current_budget || (numerator==0x80000000u && current_budget==UINT32_MAX)) abort();
                uint32_t proportional=(uint32_t)(sv(numerator)/sv(current_budget));
                if(sv(burst)<=sv(proportional)) burst=proportional;
            }
            if(started) {
                (void)h2_network_observer_measure_rate_b(m,clock,observer,index);
                uint32_t measured=h2_network_observer_measure_rate_a(m,clock,observer,index);
                uint32_t saved_burst=h2_read32(m,entry+0x498),saved_budget=h2_read32(m,entry+0x494);
                h2_write32(m,entry+0x4fc,saved_burst);
                uint32_t metric=h2_read32(m,entry+0x4b0);h2_write32(m,entry+0x4f8,saved_budget);
                uint32_t saved_rate=h2_read32(m,entry+0x49c);
                h2_write32(m,entry+0x504,metric);h2_write32(m,entry+0x508,measured);
                *h2_ptr(m,entry+0x4f4,1)=1;h2_write32(m,entry+0x500,saved_rate);
                memset(h2_ptr(m,entry+0x50c,3),0,3);
                h2_network_observer_apply_rate(m,observer,index,rate,budget,burst);
                h2_write32(m,entry+0x4dc,2);
                uint32_t count=h2_read32(m,observer+0x4f40)+1;
                *h2_ptr(m,observer+0x4f3c,1)=1;h2_write32(m,observer+0x4f40,count);
            }
            h2_write32(m,entry+0x4e8,ticks(m,clock));
        }
    }
    *h2_ptr(m,exhausted,1)=0;return started;
}
