#include "halo2/network_game_route_select.h"
#include "internal/memory.h"
void h2_network_game_select_routes(h2_memory *m,uint32_t remaining,uint32_t pending,uint32_t allowed,uint32_t selected,uint8_t reserve,uint32_t local,uint32_t deferred) {
    for(uint32_t i=0;i<16;++i) {
        uint32_t mask=h2_read32(m,pending),bit=1u<<i;
        if(!(mask&bit)||!(allowed&bit)) continue;
        uint32_t count=h2_read32(m,remaining);
        if(!count || (count&0x80000000u) || (reserve && local==i)) continue;
        if(count==1 && reserve) {
            uint8_t stop=*h2_ptr(m,deferred,1)!=0 || bit!=mask;
            *h2_ptr(m,deferred,1)=stop;
            if(stop) return;
        }
        uint8_t *p=h2_ptr(m,selected,2);
        uint32_t word=p[0]|((uint32_t)p[1]<<8);word|=bit;
        p[0]=(uint8_t)word;p[1]=(uint8_t)(word>>8);
        h2_write32(m,pending,h2_read32(m,pending)&~bit);
        h2_write32(m,remaining,h2_read32(m,remaining)-1);
    }
}
