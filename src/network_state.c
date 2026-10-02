#include "halo2/network_state.h"
#include "halo2/network_endpoint.h"
#include "internal/memory.h"
#include <string.h>
uint8_t h2_network_state_initialize(h2_memory *m,const h2_network_state_operations *ops,uint32_t state,uint32_t a,uint32_t b,uint32_t c,uint32_t config) {
    h2_write32(m,state+4,a);h2_write32(m,state+0x10,config);
    h2_write32(m,state+0xc,c);h2_write32(m,state+8,b);
    memset(h2_ptr(m,state+0x14,0x90),0,0x90);
    uint32_t bits=h2_read32(m,h2_read32(m,state+0x10)+0xf8);
    int32_t interval;memcpy(&interval,&bits,4);
    h2_network_statistics_initialize(m,state+0x4e30,interval);
    uint8_t override=*h2_ptr(m,0x510548,1);
    *h2_ptr(m,state+0x4f3c,1)=1;*h2_ptr(m,state+0x4f3d,1)=0;*h2_ptr(m,state+0x4f3e,1)=0;
    h2_write32(m,state+0x4f38,UINT32_MAX);
    uint32_t stamp=override ? h2_read32(m,0x51054c) : ops->ticks(ops->context);
    h2_write32(m,state+0x4f30,stamp);
    stamp=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : ops->ticks(ops->context);
    h2_write32(m,state+0x4f34,stamp);
    for (uint32_t i=0;i<15;i++) {
        uint32_t entry=state+0xa8+i*0x528;
        memset(h2_ptr(m,entry,0x528),0,0x528);
        h2_write32(m,entry+0xc,UINT32_MAX);h2_write32(m,entry+0x70,UINT32_MAX);
    }
    *h2_ptr(m,state+0x4e00,1)=0;
    return 1;
}
uint8_t h2_network_global_state_initialize(h2_memory *m,uint32_t dependency) {
    memset(h2_ptr(m,0x4cd868,0x7d8),0,0x7d8);
    h2_write32(m,0x4ce03c,dependency);
    *h2_ptr(m,0x4cd868,1)=1;
    h2_write32(m,0x4cd900,UINT32_MAX);
    return 1;
}
void h2_network_provider_initialize(h2_memory *m,const h2_network_state_operations *ops) {
    uint32_t provider=h2_read32(m,0x477058);
    if (!provider) return;
    uint32_t function=h2_read32(m,provider+0x10);
    if (!function) return;
    uint8_t result=ops->provider_initialize(ops->context,function,0x477058);
    uint8_t *flags=h2_ptr(m,0x47705c,1);
    if (result) *flags|=0xa; else *flags&=0xf5;
}

uint8_t h2_network_auxiliary_initialize(h2_memory *m, uint32_t a, uint32_t b) {
    h2_write32(m, 0x4cf8e4, a);
    *h2_ptr(m, 0x4cf95c, 1) = 0;
    *h2_ptr(m, 0x4cf964, 1) = 0;
    *h2_ptr(m, 0x4cf8ec, 1) = 0;
    h2_write32(m, 0x4cf8e8, b);
    h2_write32(m, 0x4cf968, UINT32_MAX);
    h2_write32(m, 0x4cf96c, 0x10);
    memset(h2_ptr(m, 0x4cf8f0, 0x6c), 0, 0x6c);
    *h2_ptr(m, 0x4cf8e0, 1) = 1;
    return 1;
}

void h2_network_tracking_reset(h2_memory *m) {
    memset(h2_ptr(m, 0x4d8ba8, 0x80), 0xff, 0x80);
    for (uint32_t i = 0; i < 32; ++i) {
        uint32_t p = 0x4d8c28+i*0x14;
        h2_write32(m, p, 0);
        h2_write32(m, p+4, UINT32_MAX);
        h2_write32(m, p+8, 0);
        h2_write32(m, p+12, 0);
        /* The fifth word is retained. */
    }
}
