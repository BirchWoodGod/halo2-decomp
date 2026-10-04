#include "halo2/network_session_handoff_remove.h"
#include "internal/memory.h"
void h2_network_session_remove_handoff_candidate(h2_memory *m,const h2_network_state_operations *clock,uint32_t session,uint32_t peer) {
    uint32_t mask=h2_read32(m,session+0x7424)&~(UINT32_C(1)<<(peer&31));
    uint8_t selected=h2_read32(m,session+0x742c)==peer;
    h2_write32(m,session+0x7424,mask);
    if(!selected) return;
    uint8_t cached=*h2_ptr(m,0x510548,1);
    *h2_ptr(m,session+0x743c,1)=0;*h2_ptr(m,session+0x7430,1)=0;
    h2_write32(m,session+0x742c,UINT32_MAX);
    uint32_t now=cached ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,session+0x7428,now);
}
