#include "halo2/network_observer_metrics.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>
static int64_t signed32(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static float read_float(h2_memory *m,uint32_t p) {uint32_t bits=h2_read32(m,p);float value;memcpy(&value,&bits,4);return value;}
uint8_t h2_network_observer_get_metrics(h2_memory *m,uint32_t observer,uint32_t index,uint32_t metric,uint32_t rate,uint32_t sample,uint32_t ratio) {
    if(index>=15) return 0;
    uint32_t entry=observer+0xa8+index*0x528;
    if(!h2_read32(m,entry) || !*h2_ptr(m,entry+0x48c,1)) return 0;
    h2_write32(m,metric,h2_read32(m,entry+0x4b0));
    h2_write32(m,rate,h2_read32(m,entry+0x49c));
    h2_write32(m,sample,h2_read32(m,entry+0x514));
    volatile float numerator=(float)signed32(h2_read32(m,entry+0x358));
    volatile float denominator=(float)signed32(h2_read32(m,entry+0x250));
    volatile float quotient=numerator/denominator;
    volatile float product=quotient*read_float(m,0x445420);
    double value=product;
    uint32_t result=!isfinite(value)||value < -2147483648.0||value >= 2147483648.0 ? 0x80000000u : (uint32_t)(int64_t)value;
    h2_write32(m,ratio,result);return 1;
}
void h2_network_observer_apply_rate(h2_memory *m,uint32_t observer,uint32_t index,float rate,uint32_t budget,uint32_t burst) {
    uint32_t entry=observer+0xa8+index*0x528;
    uint8_t limited=h2_network_observer_rate_limited(m,observer,rate,*h2_ptr(m,entry+0x48d,1),*h2_ptr(m,entry+0x48e,1),*h2_ptr(m,entry+0x490,1));
    uint32_t bits;memcpy(&bits,&rate,4);
    h2_write32(m,entry+0x494,budget);h2_write32(m,entry+0x49c,bits);
    *h2_ptr(m,entry+0x4a0,1)=limited;h2_write32(m,entry+0x498,burst);
}
