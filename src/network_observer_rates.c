#include "halo2/network_observer_rates.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>
static int64_t sv(uint32_t x) {return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;}
static float rf(h2_memory *m,uint32_t a) {uint32_t x=h2_read32(m,a);float f;memcpy(&f,&x,4);return f;}
static float cv(uint32_t x) {volatile float f=(float)sv(x);return f;}
static float mul(float a,float b) {volatile float f=a*b;return f;}
static float scale(h2_memory *m) {const uint8_t *p=h2_ptr(m,0x485ac0,2);return rf(m,p[0]==50 && !p[1] ? 0x45e0d8 : 0x45dcfc);}
float h2_network_observer_next_rate(h2_memory *m,uint32_t observer,float current,uint8_t capped) {
    float multiplier=scale(m),sentinel=rf(m,0x44aed4),selected=sentinel;
    uint32_t config=h2_read32(m,observer+16),count=h2_read32(m,config+0x9c);
    /* The original unrolled loop visits the table from highest index down. */
    for(uint32_t i=count;sv(i)>0;--i) {
        float candidate=mul(rf(m,config+0x9c+i*4),multiplier);
        if(candidate>current && selected>candidate) selected=candidate;
    }
    if(selected==sentinel) selected=current;
    if(capped) {float cap=mul(multiplier,rf(m,0x45dbbc));if(selected>cap) selected=cap;}
    return selected;
}
float h2_network_observer_select_rate(h2_memory *m,uint32_t observer,uint32_t budget,uint8_t alternate,uint8_t capped) {
    float multiplier=scale(m);
    uint32_t config=h2_read32(m,observer+16),count=h2_read32(m,config+0x9c);
    volatile float threshold=cv(budget)/cv(h2_read32(m,config+(alternate ? 0x10c : 0x108))*8u+0x168);
    float selected=0;uint8_t found=0;
    for(uint32_t i=0;sv(i)<sv(count-1);++i) {
        selected=mul(rf(m,config+0xa0+i*4),multiplier);
        if(threshold>=selected) {
            float sentinel=rf(m,0x45dbd8);
            found=isunordered(selected,sentinel) || selected!=sentinel;
            break;
        }
    }
    if(!found) selected=mul(rf(m,config+0x9c+count*4),multiplier);
    if(capped) {float cap=mul(multiplier,rf(m,0x45dbbc));if(selected>cap) selected=cap;}
    return selected;
}
uint32_t h2_network_observer_rate_budget(h2_memory *m,uint32_t observer,uint8_t alternate,float rate) {
    uint32_t config=h2_read32(m,observer+16);
    float product=mul(cv(h2_read32(m,config+(alternate ? 0x10c : 0x108))*8u+0x168),rate);
    double rounded=nearbyint((double)product);
    return !isfinite(rounded)||rounded < -2147483648.0||rounded > 2147483647.0 ? 0x80000000u : (uint32_t)(int64_t)rounded;
}
uint8_t h2_network_observer_rate_limited(h2_memory *m,uint32_t observer,float rate,uint8_t configured,uint8_t baseline,uint8_t capped) {
    float multiplier=scale(m);volatile float margin=rate+rf(m,0x45dbdc);
    uint8_t limited=0;
    if(configured) limited=mul(rf(m,h2_read32(m,observer+16)+0x110),multiplier)>margin;
    if(baseline) {
        if(capped) multiplier=mul(multiplier,rf(m,0x45dbbc));
        if(multiplier>margin) limited=1;
    }
    return limited;
}
