#include "halo2/network_observer_bandwidth_allocate.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t maximum(uint32_t a,uint32_t b) {return sv(a)>sv(b) ? a : b;}
static float cv(uint32_t v) {volatile float f=(float)sv(v);return f;}
static float rf(h2_memory *m,uint32_t p) {uint32_t b=h2_read32(m,p);float f;memcpy(&f,&b,4);return f;}
static float mul(float a,float b) {volatile float v=a*b;return v;}
static uint32_t convert(float f,int rounded) {
    double v=rounded ? nearbyint((double)f) : trunc((double)f);
    return !isfinite(v)||v < -2147483648.0||v > 2147483647.0 ? 0x80000000u : (uint32_t)(int64_t)v;
}
static uint32_t divide(uint32_t a,uint32_t b) {
    if(!b || (a==0x80000000u && b==UINT32_MAX)) abort();
    return (uint32_t)(sv(a)/sv(b));
}
void h2_network_observer_allocate_bandwidth(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528;
    uint32_t connection=h2_read32(m,0x4d87d4)+h2_read32(m,entry+12)*0xf8;
    uint32_t count=0,sum=0;
    for(uint32_t i=0;i<15;i++) {
        uint32_t peer=observer+0xa8+i*0x528;
        if(h2_read32(m,peer) && *h2_ptr(m,peer+0x48c,1)) {count++;sum+=h2_read32(m,peer+0x494);}
    }
    uint32_t config=h2_read32(m,observer+16),budget=h2_read32(m,config+0x158),demand=budget+sum;
    uint32_t available=h2_read32(m,observer+0x4e04),cap;
    if(*h2_ptr(m,observer+0x4e01,1)) {cap=h2_read32(m,config+0x160);available=(uint32_t)(sv(available*3u)/4);}
    else {cap=h2_read32(m,config+0x15c);available=(uint32_t)(sv(available)/2);}
    if(sv(available)>sv(cap)) available=cap;
    uint32_t previous=h2_read32(m,observer+0x4f2c);
    uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    config=h2_read32(m,observer+16);
    if(sv(now-previous)<=sv(h2_read32(m,config+0x154))) available=maximum(available,(count+1)*h2_read32(m,config+0x164));
    if(sv(demand)>sv(available)) {
        uint32_t total=maximum(sum,available);
        budget=maximum(divide(total,count+1),h2_read32(m,h2_read32(m,observer+16)+0x14c));
        if(count && cv(sum)>rf(m,0x45dbd8)) {
            volatile float scale=cv(total-budget)/cv(sum);
            for(uint32_t i=0;i<15;i++) {
                uint32_t peer=observer+0xa8+i*0x528;
                if(!h2_read32(m,peer) || !*h2_ptr(m,peer+0x48c,1)) continue;
                uint32_t new_budget=convert(mul(cv(h2_read32(m,peer+0x494)),scale),1);
                uint32_t burst=convert(mul(cv(h2_read32(m,peer+0x498)),scale),1);
                config=h2_read32(m,observer+16);
                new_budget=maximum(new_budget,h2_read32(m,config+0x14c));burst=maximum(burst,h2_read32(m,config+0xe0));
                float rate=h2_network_observer_select_rate(m,observer,new_budget,*h2_ptr(m,entry+0x48e,1),*h2_ptr(m,entry+0x490,1));
                h2_network_observer_apply_rate(m,observer,i,rate,new_budget,burst);
            }
        }
    }
    memset(h2_ptr(m,entry+0x48c,0x94),0,0x94);
    *h2_ptr(m,entry+0x48c,1)=1;
    uint32_t provider=h2_read32(m,connection+0x3c);
    *h2_ptr(m,entry+0x48e,1)=provider!=0;
    provider=h2_read32(m,connection+0x3c);
    *h2_ptr(m,entry+0x48f,1)=provider && *h2_ptr(m,provider+0x30,1);
    provider=h2_read32(m,connection+0x3c);
    uint8_t capped=provider && !*h2_ptr(m,provider+0x30,1);
    h2_write32(m,entry+0x4e0,UINT32_MAX);h2_write32(m,entry+0x4e4,UINT32_MAX);h2_write32(m,entry+0x4e8,UINT32_MAX);
    *h2_ptr(m,entry+0x490,1)=capped;h2_write32(m,entry+0x4dc,0);
    uint32_t latency=0;
    if(h2_read32(m,connection+0x54)==5 && (*h2_ptr(m,connection+0x48,1)&8)) latency=h2_read32(m,h2_read32(m,0x4d87d8)+h2_read32(m,connection+0x10)*0x97c+0x96c);
    h2_write32(m,entry+0x4f0,latency);
    latency=maximum(latency,h2_read32(m,h2_read32(m,observer+16)+0x16c));
    h2_write32(m,entry+0x4f0,latency);h2_write32(m,entry+0x4ec,0);h2_write32(m,entry+0x4b0,latency);h2_write32(m,entry+0x4b4,0);
    float rate=h2_network_observer_select_rate(m,observer,budget,*h2_ptr(m,entry+0x48e,1),capped);
    uint32_t steps=convert(mul(mul(cv(latency),rate),rf(m,0x45dc70)),0)+1;
    uint32_t burst=(steps+1)*divide(latency*budget,steps*8000u);
    burst=maximum(burst,h2_read32(m,h2_read32(m,observer+16)+0xe0));
    h2_network_observer_apply_rate(m,observer,index,rate,budget,burst);
}
