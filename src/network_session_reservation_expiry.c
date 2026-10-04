#include "halo2/network_session_reservation_expiry.h"
#include "internal/memory.h"
void h2_network_session_expire_reservations(h2_memory *m,const h2_network_state_operations *clock,uint32_t session) {
    uint32_t first=session+0x7668,end=first+0x240;
    for(uint32_t p=first;p<end;p+=0x24) {
        if(!*h2_ptr(m,p,1) || h2_read32(m,p+0x20)==UINT32_MAX) continue;
        uint32_t previous=h2_read32(m,p+0x1c);
        uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
        if(now-previous>h2_read32(m,p+0x20)) *h2_ptr(m,p,1)=0;
    }
}
