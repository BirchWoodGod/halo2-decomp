#include "halo2/network_observer_bandwidth.h"
#include "halo2/network_endpoint.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>

static int64_t sv(uint32_t x) {return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;}
static uint32_t rd(h2_memory *m,uint32_t a) {return h2_read32(m,a);}
static void wr(h2_memory *m,uint32_t a,uint32_t x) {h2_write32(m,a,x);}
static float rf(h2_memory *m,uint32_t a) {uint32_t x=rd(m,a);float f;memcpy(&f,&x,4);return f;}
static void wf(h2_memory *m,uint32_t a,float f) {uint32_t x;memcpy(&x,&f,4);wr(m,a,x);}
static float mul(float a,float b) {volatile float f=a*b;return f;}
static float divf(float a,float b) {volatile float f=a/b;return f;}
static float add(float a,float b) {volatile float f=a+b;return f;}
static float cv(uint32_t x) {volatile float f=(float)sv(x);return f;}
static uint32_t rounded(float f) {
    double r=nearbyint((double)f);
    return !isfinite(r)||r < -2147483648.0||r > 2147483647.0 ? 0x80000000u : (uint32_t)(int64_t)r;
}
static uint32_t tick(h2_memory *m,const h2_network_state_operations *c) {
    return *h2_ptr(m,0x510548,1) ? rd(m,0x51054c) : c->ticks(c->context);
}
static float rate(h2_memory *m,uint32_t config,float scale,float budget) {
    uint32_t count=rd(m,config+0x9c);
    float threshold=divf(budget,cv(rd(m,config+0x10c)*8u+0x168));
    for(uint32_t i=0;sv(i)<sv(count-1);++i) {
        float value=mul(rf(m,config+0xa0+i*4),scale);
        if(threshold>=value) {
            if(value!=0.0f) return value;
            break;
        }
    }
    return mul(rf(m,config+0x9c+count*4),scale);
}
void h2_network_observer_update_bandwidth(h2_memory *m,const h2_network_state_operations *clock,uint32_t o) {
    uint32_t previous=rd(m,o+0x4f08),now=tick(m,clock),config=rd(m,o+16);
    if(sv(now-previous)<sv(rd(m,config+0x118))) return;
    uint32_t eligible=0,congested=0;
    if(*h2_ptr(m,o+0x4e00,1)) {
        for(uint32_t i=0;i<15;++i) {
            uint32_t p=o+0x514+i*0x528;
            if(rd(m,p-0x46c)!=7 || sv(rd(m,p))>sv(rd(m,config+0x100))) continue;
            ++eligible;
            if(divf(cv(rd(m,p-4)),cv(rd(m,p-0x10c)))>=rf(m,config+0x104)) ++congested;
        }
    }
    uint32_t counter=eligible && divf(cv(congested),cv(eligible))>=rf(m,config+0x11c) ? 0x4f14 : 0x4f10;
    uint32_t value=rd(m,o+counter)+1;
    wr(m,o+(counter==0x4f14 ? 0x4f10 : 0x4f14),0);
    uint32_t limit=rd(m,config+0x130);
    wr(m,o+counter,sv(value)>sv(limit) ? limit : value);
    if(*h2_ptr(m,o+0x4e00,1)) {
        h2_network_statistics_advance(m,clock,o+0x4e30);
        uint32_t estimate=rounded(mul(mul(mul(cv(rd(m,o+0x4f00)),rf(m,o+0x4e54)),rf(m,0x45dc18)),rf(m,0x45dfec)));
        config=rd(m,o+16);
        if(sv(rd(m,o+0x4f14))>=sv(rd(m,config+0x120))) {
            previous=rd(m,o+0x4f0c);now=tick(m,clock);config=rd(m,o+16);
            if(sv(now-previous)>=sv(rd(m,config+0x128))) {
                uint32_t decreased=estimate-rd(m,config+0x124),v=rd(m,o+0x4e20);
                if(sv(v)>sv(decreased)) v=decreased;
                limit=rd(m,config+0x138);if(sv(v)<=sv(limit)) v=limit;
                wr(m,o+0x4e20,v);wr(m,o+0x4e28,v);
                v=rd(m,o+0x4e24);wr(m,o+0x4e24,sv(v)>sv(estimate) ? estimate : v);
                now=tick(m,clock);wr(m,o+0x4f0c,now);
            }
        } else if(sv(rd(m,o+0x4f10))>=sv(rd(m,config+0x12c))) {
            if(sv(estimate)>sv(rd(m,o+0x4e20))) wr(m,o+0x4e20,estimate);
            value=rd(m,config+0x140)+(*h2_ptr(m,o+0x4f18,1) ? rd(m,o+0x4e28) : estimate);
            if(sv(value)>sv(rd(m,o+0x4e28)) && sv(rd(m,config+0x13c)+value)<sv(rd(m,o+0x4e24))) {
                wr(m,o+0x4e28,value);wr(m,o+0x4f10,0);
            }
        }
    }
    uint32_t base=rd(m,0x4d87d4),zero=rd(m,0x45dbcc),indices[15],count=0;
    for(uint32_t i=0;i<15;++i) {
        uint32_t e=o+0xa8+i*0x528,state=rd(m,e);
        wr(m,e+0x480,UINT32_MAX);wr(m,e+0x484,zero);wr(m,e+0x488,UINT32_MAX);
        uint32_t id=rd(m,e+12);
        if(state==7 && id!=UINT32_MAX && rd(m,base+id*0xf8+0x3c)) indices[count++]=i;
    }
    if(count) {
        wr(m,o+0x4f1c,count);
        if(*h2_ptr(m,o+0x4e00,1)) {
            uint32_t budget=(uint32_t)(sv(rd(m,o+0x4e28)<<10)/count);
            wr(m,o+0x4f20,budget);
            const uint8_t *p=h2_ptr(m,0x485ac0,2);
            float scale=rf(m,(p[0]==50 && p[1]==0) ? 0x45e0d8 : 0x45dcfc);
            config=rd(m,o+16);
            float first=rate(m,config,scale,cv(budget));wf(m,o+0x4f24,first);
            float second=rate(m,config,scale,cv(budget)),cap=mul(scale,rf(m,0x45dbbc));
            if(second>cap) second=cap;
            wf(m,o+0x4f28,second);
            float margin=add(first,rf(m,0x45dbdc));
            *h2_ptr(m,o+0x4f18,1)=scale>margin || mul(rf(m,config+0x110),scale)>margin;
        } else {
            wr(m,o+0x4f20,UINT32_MAX);wr(m,o+0x4f24,zero);wr(m,o+0x4f28,zero);*h2_ptr(m,o+0x4f18,1)=0;
        }
    }
    for(uint32_t i=0;i<count;++i) {
        uint32_t e=o+0xa8+indices[i]*0x528,connection=rd(m,0x4d87d4)+rd(m,e+12)*0xf8;
        uint32_t budget=rd(m,o+0x4f20);wr(m,e+0x480,budget);
        uint32_t object=rd(m,connection+0x3c);
        wr(m,e+0x484,rd(m,o+((object && *h2_ptr(m,object+0x30,1)) ? 0x4f24 : 0x4f28)));
        if(sv(budget)<0) {wr(m,e+0x488,UINT32_MAX);continue;}
        uint32_t a=0,b=0;
        if(rd(m,connection+0x54)==5 && (*h2_ptr(m,connection+0x48,1)&8)) {
            uint32_t stream=rd(m,0x4d87d8)+rd(m,connection+0x10)*0x97c;
            a=rd(m,stream+0x96c);b=rd(m,stream+0x970);
        }
        value=(uint32_t)(sv((a+b*2)*budget)/8000);
        limit=rd(m,rd(m,o+16)+0xe0);wr(m,e+0x488,sv(value)<=sv(limit) ? limit : value);
    }
    now=tick(m,clock);wr(m,o+0x4f08,now);
}
