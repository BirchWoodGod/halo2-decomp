#include "halo2/network_observer_probe_update.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
void h2_network_observer_update_probe(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer,uint32_t index,uint32_t scratch) {
    uint32_t entry=observer+0xa8+index*0x528,state=h2_read32(m,entry+0x4dc);
    if(!state) {
        uint32_t previous=h2_read32(m,entry+0x4e0),elapsed=0;
        if(previous!=UINT32_MAX) {
            uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
            elapsed=now-previous;
        }
        uint32_t config=h2_read32(m,observer+16);
        if(h2_read32(m,entry+0x4e0)!=UINT32_MAX && sv(elapsed)<sv(h2_read32(m,config+0x1f0))) return;
        if(sv(h2_read32(m,entry+0x518))<sv(h2_read32(m,config+0x1ec))) return;
        h2_write32(m,entry+0x4dc,1);*h2_ptr(m,observer+0x4f3c,1)=1;return;
    }
    if(sv(h2_read32(m,entry+0x51c))>0) {
        h2_network_observer_reset_probe(m,clock,observer,index);return;
    }
    if(state==2) {
        uint32_t result=h2_network_observer_probe_result(m,clock,observer,index);
        if(!result) h2_write32(m,entry+0x4dc,3);
        else if(result==1) h2_network_observer_restore_probe(m,observer,index);
        else h2_network_observer_reduce_bandwidth(m,clock,observer,index,1);
        return;
    }
    uint32_t config=h2_read32(m,observer+16);
    uint32_t offset=h2_read32(m,config+(*h2_ptr(m,entry+0x48e,1) ? 0x1d8 : 0x1d4));
    *h2_ptr(m,scratch,1)=0;
    if(*h2_ptr(m,entry+0x4c0,1) || sv(h2_read32(m,entry+0x4d8))>0) return;
    uint32_t delta=h2_read32(m,entry+0x4b0)-h2_read32(m,entry+0x4b4);
    uint32_t limit=h2_read32(m,entry+0x4f0)+offset;
    if(sv(delta)>sv(limit)) {h2_network_observer_probe_failure(m,clock,observer,index);return;}
    if(h2_network_observer_start_probe(m,clock,observer,index,scratch)) return;
    if(*h2_ptr(m,scratch,1)) h2_network_observer_reset_probe(m,clock,observer,index);
}
