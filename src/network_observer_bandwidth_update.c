#include "halo2/network_observer_bandwidth_update.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *c) {return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);}
void h2_network_observer_commit_bandwidth(h2_memory *m,const h2_network_state_operations *clock,uint32_t observer) {
    uint32_t previous=h2_read32(m,observer+0x4f38),elapsed=ticks(m,clock)-previous;
    uint32_t config=h2_read32(m,observer+16);
    if(*h2_ptr(m,observer+0x4f3c,1) || sv(elapsed)>=sv(h2_read32(m,config+0x19c))) {
        if(*h2_ptr(m,observer+0x4f3d,1)) {
            for(uint32_t i=0;i<15;++i) {
                uint32_t e=observer+0xa8+i*0x528;
                if(h2_read32(m,e) && *h2_ptr(m,e+0x48c,1)) {
                    uint32_t state=h2_read32(m,e+0x4dc);
                    if(state==2 || state==3) h2_network_observer_restore_probe(m,observer,i);
                }
            }
        } else if(sv(elapsed)>=sv(h2_read32(m,config+0x1a4))) {
            uint32_t blocked=0,count=0,qualified=0,total=0;
            for(uint32_t i=0;i<15;++i) {
                uint32_t e=observer+0xa8+i*0x528;
                if(!h2_read32(m,e)||!*h2_ptr(m,e+0x48c,1)) continue;
                uint32_t b=h2_network_observer_measure_rate_b(m,clock,observer,i);
                uint32_t a=h2_network_observer_measure_rate_a(m,clock,observer,i);
                uint8_t sufficient=!*h2_ptr(m,e+0x4a1,1) || sv(a)>=sv(h2_read32(m,h2_read32(m,observer+16)+0x1a8));
                ++count;blocked+=sv(h2_read32(m,e+0x4d8))>0;
                if(sufficient && !*h2_ptr(m,e+0x4a0,1)) ++qualified;
                h2_write32(m,e+0x510,b);total+=a;h2_write32(m,e+0x514,a);
            }
            if(!blocked) h2_network_observer_record_measurement(m,clock,observer,total,count,qualified);
        }
        if(*h2_ptr(m,observer+0x4f3e,1)) {
            uint32_t total=0,count=0;
            for(uint32_t i=0;i<15;++i) {
                uint32_t e=observer+0xa8+i*0x528;
                if(!h2_read32(m,e)||!*h2_ptr(m,e+0x48c,1)) continue;
                ++count;previous=h2_read32(m,observer+0x4f38);
                uint32_t delta=ticks(m,clock)-previous;
                if(sv(delta)>0) total+=(uint32_t)(sv(h2_read32(m,e+0x4a4)*8000u)/sv(delta));
            }
            if(count) {
                uint32_t average=h2_read32(m,observer+0x4e0c);
                if(average!=UINT32_MAX) {
                    uint32_t shift=h2_read32(m,h2_read32(m,observer+16)+0x1b4)&31,delta=total-average,adjusted=delta>>shift;
                    if(shift && (delta&0x80000000u)) adjusted|=UINT32_MAX<<(32-shift);
                    total=average+adjusted;
                }
                h2_write32(m,observer+0x4e0c,total);
            }
        }
        h2_network_observer_finish_cycle(m,clock,observer);
    }
    *h2_ptr(m,observer+0x4f3c,1)=0;*h2_ptr(m,observer+0x4f3d,1)=0;*h2_ptr(m,observer+0x4f3e,1)=0;
}
