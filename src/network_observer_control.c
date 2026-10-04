#include "halo2/network_observer_control.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>
static int64_t sv(uint32_t x) {return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *c) {return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);}
static float rf(h2_memory *m,uint32_t p) {uint32_t b=h2_read32(m,p);float f;memcpy(&f,&b,4);return f;}
static uint8_t compare(void *m,uint32_t a,uint32_t b,uint32_t data) {return h2_network_observer_compare_priority(m,a,b,data);}
void h2_network_observer_control_bandwidth(h2_memory *m,const h2_network_state_operations *clock,const h2_observer_control_callbacks *callbacks,uint32_t observer,uint32_t scratch) {
    uint8_t enabled=*h2_ptr(m,observer+0x4e00,1);
    for(uint32_t i=0;i<15;++i) {
        uint32_t e=observer+0xa8+i*0x528;
        if(!h2_read32(m,e)) continue;
        uint32_t connection=h2_read32(m,0x4d87d4)+h2_read32(m,e+12)*0xf8;
        if(*h2_ptr(m,e+0x48c,1)) {
            uint8_t keep=0;
            if(enabled && h2_read32(m,connection+0x54)==5) {
                uint32_t provider=h2_read32(m,connection+0x3c);
                if((provider!=0)==*h2_ptr(m,e+0x48e,1)) {
                    uint8_t flag=provider && *h2_ptr(m,provider+0x30,1);
                    keep=flag==*h2_ptr(m,e+0x48f,1);
                }
            }
            if(!keep) {*h2_ptr(m,e+0x48c,1)=0;*h2_ptr(m,observer+0x4f3c,1)=1;}
        }
        if(h2_read32(m,connection+0x54)==5 && enabled && !*h2_ptr(m,e+0x48c,1)) {
            h2_network_observer_allocate_bandwidth(m,clock,observer,i);*h2_ptr(m,observer+0x4f3c,1)=1;
        }
        if(!*h2_ptr(m,e+0x48c,1)) continue;
        uint8_t active=0;
        for(uint32_t j=0;j<4;++j) {
            if(!(*h2_ptr(m,e+9,1)&(1u<<j))) continue;
            uint32_t object=h2_read32(m,observer+0x14+j*0x24),vtable=h2_read32(m,object);
            if((uint8_t)callbacks->invoke(callbacks->context,h2_read32(m,vtable+4),object,i)) {active=1;break;}
        }
        if(*h2_ptr(m,0x4c99b8,1)&&*h2_ptr(m,0x476fcc,1)&&h2_read32(m,0x4c9888)) {
            uint32_t kind=h2_read32(m,0x4c988c),session=0;
            if((kind==1||kind==2)&&*h2_ptr(m,0x527330,1)) {
                uint32_t candidate=h2_read32(m,kind==1 ? 0x527364 : 0x52736c);
                if(h2_read32(m,candidate+0x741c)) session=candidate;
            }
            if(session) {
                uint32_t peer=callbacks->invoke(callbacks->context,h2_read32(m,h2_read32(m,session)+0x14),session,i);
                if(peer!=UINT32_MAX && h2_network_game_peer_active(m,peer,scratch+120)) active=1;
            }
        }
        if(active!=*h2_ptr(m,e+0x48d,1)) *h2_ptr(m,e+0x48d,1)=active;
    }
    for(uint32_t i=0;i<15;++i) {
        uint32_t e=observer+0xa8+i*0x528;
        if(!h2_read32(m,e)||!*h2_ptr(m,e+0x48c,1)||!*h2_ptr(m,e+0x4f4,1)) continue;
        uint32_t config=h2_read32(m,observer+16),offset=h2_read32(m,config+(*h2_ptr(m,e+0x48e,1) ? 0x1dc : 0x1d4));
        if(sv(h2_read32(m,e+0x4b0)-h2_read32(m,e+0x4b4))>sv(h2_read32(m,e+0x504)+offset))
            h2_network_observer_reduce_bandwidth(m,clock,observer,i,1);
    }
    uint32_t previous=h2_read32(m,observer+0x4f30),elapsed=ticks(m,clock)-previous;
    if(sv(elapsed)>=sv(h2_read32(m,h2_read32(m,observer+16)+0x148))) {
        memset(h2_ptr(m,scratch,60),0,60);h2_write32(m,observer+0x4f40,0);
        uint32_t count=0;
        for(uint32_t i=0;i<15;++i) {
            uint32_t e=observer+0xa8+i*0x528;
            if(!h2_read32(m,e)||!*h2_ptr(m,e+0x48c,1)) continue;
            h2_write32(m,scratch+60+count++*4,i);
            float priority=h2_network_observer_probe_priority(m,clock,observer,i);uint32_t bits;memcpy(&bits,&priority,4);h2_write32(m,scratch+i*4,bits);
        }
        volatile float product=(float)count*rf(m,h2_read32(m,observer+16)+0x1c4);
        double rounded=nearbyint((double)product);
        uint32_t limit=!isfinite(rounded)||rounded < -2147483648.0||rounded > 2147483647.0 ? 0x80000000u : (uint32_t)(int64_t)rounded;
        h2_write32(m,observer+0x4f44,limit);
        if(sv(limit)<1) limit=1;
        else {uint32_t cap=h2_read32(m,h2_read32(m,observer+16)+0x1c0);if(sv(limit)>sv(cap)) limit=cap;}
        h2_write32(m,observer+0x4f44,limit);
        h2_sort_u32(m,compare,m,scratch+60,count,scratch);
        for(uint32_t i=0;i<count;++i) h2_network_observer_update_probe(m,clock,observer,h2_read32(m,scratch+60+i*4),scratch+148);
        h2_network_observer_commit_bandwidth(m,clock,observer);
        for(uint32_t i=0;i<15;++i) {
            uint32_t e=observer+0xa8+i*0x528;
            if(h2_read32(m,e)&&*h2_ptr(m,e+0x48c,1)&&h2_read32(m,e+0x4dc)==3) {h2_write32(m,e+0x4dc,1);h2_write32(m,e+0x4ec,0);}
        }
        h2_write32(m,observer+0x4f30,ticks(m,clock));
    }
    h2_network_observer_commit_bandwidth(m,clock,observer);
}
