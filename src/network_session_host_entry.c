#include "halo2/network_session_host_entry.h"
#include "halo2/network_session_snapshot_reset.h"
#include "internal/memory.h"
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
void h2_network_session_begin_host(h2_memory *m,const h2_network_state_operations *clock,uint32_t session) {
    uint32_t state=h2_read32(m,session+0x741c);
    if(state<5 || state>8) {
        h2_network_session_reset_snapshots(m,session,1);
        uint8_t active=0;
        for(uint32_t i=0;sv(i)<sv(h2_read32(m,session+0x54));++i) {
            uint32_t peer=session+0x72de + i*20;
            uint8_t flag=*h2_ptr(m,peer-1,1);*h2_ptr(m,peer,1)=flag;
            if(flag) active=1;
        }
        if(active) {
            h2_write32(m,session+0x7660,h2_read32(m,session+0x4980));
            uint8_t cached=*h2_ptr(m,0x510548,1);
            *h2_ptr(m,session+0x765c,1)=1;
            uint32_t now=cached ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
            h2_write32(m,session+0x7664,now);
        }
        h2_write32(m,session+0x40,h2_read32(m,session+0x72d8));
    }
    for(uint32_t i=0;i<0x1f8;i+=4) h2_write32(m,session+0x7420+i,0);
    h2_write32(m,session+0x741c,5);
}
