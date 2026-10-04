#include "halo2/network_observer_route_mode.h"
#include "internal/memory.h"
void h2_network_observer_update_route_mode(h2_memory *m,uint32_t observer) {
    uint8_t pending=0,provider_active=0,provider_probe=0;
    for(uint32_t i=0;i<15;++i) {
        uint32_t e=observer+0xa8+i*0x528;
        if(!h2_read32(m,e)||!*h2_ptr(m,e+0x48c,1)) continue;
        pending|=*h2_ptr(m,e+0x4c0,1);
        if(*h2_ptr(m,e+0x48e,1)) {
            provider_active|=*h2_ptr(m,e+0x48f,1)!=0;
            provider_probe|=*h2_ptr(m,e+0x50c,1)!=0||*h2_ptr(m,e+0x50e,1)!=0;
        }
    }
    uint32_t mode=0;
    if(provider_active) mode=1+(pending!=0);
    else if(*h2_ptr(m,0x4cf73c,1)&&(pending||provider_probe)) mode=1;
    if(*h2_ptr(m,0x4c99b8,1)) h2_write32(m,0x4c987c,mode);
}
