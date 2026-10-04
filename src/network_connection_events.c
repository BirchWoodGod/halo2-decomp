#include "halo2/network_connection_events.h"
#include "internal/memory.h"
#include <math.h>
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static void initialize_iterator(h2_memory *m,uint32_t p,uint32_t flags) {
    h2_write32(m,p+12,0);h2_write32(m,p+16,0);
    h2_write32(m,p,flags);h2_write32(m,p+4,UINT32_MAX);h2_write32(m,p+8,UINT32_MAX);
}
static void invoke(h2_memory *m,const h2_connection_event_callbacks *c,uint32_t object,uint32_t offset,uint32_t count,uint32_t a,uint32_t b,uint32_t d) {
    uint32_t function=h2_read32(m,h2_read32(m,object)+offset);
    c->invoke(c->context,function,object,count,a,b,d);
}
void h2_network_connection_dispatch_events(h2_memory *m,const h2_network_state_operations *clock,const h2_connection_event_callbacks *c,uint32_t connection,uint32_t scratch) {
    if(!(*h2_ptr(m,connection+0x48,1)&8)) return;
    uint32_t stream=h2_read32(m,0x4d87d8)+h2_read32(m,connection+16)*0x97c;
    h2_write32(m,scratch+0x14,stream);
    while(h2_network_stream_retire_next(m,clock,stream,0,scratch+0x18,scratch+0x1c)) {}
    uint32_t kind=h2_network_stream_poll_event(m,clock,stream,scratch+8,scratch+16,scratch+4,scratch+72);
    while(kind) {
        if(kind==4 || kind==1) {
            uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
            h2_write32(m,connection+0xd8,now);
            h2_write32(m,connection+0xe0,h2_read32(m,0x4e6398));
            h2_write32(m,connection+0xe4,h2_read32(m,0x4e639c));
            if(h2_read32(m,connection+0x54)==4) h2_write32(m,connection+0x54,5);
            uint32_t object=h2_read32(m,connection+0x40);
            if(object) invoke(m,c,object,8,3,h2_read32(m,connection+0x44),h2_read32(m,scratch+16),h2_read32(m,scratch+4));
        }
        if(kind==4) {
            uint32_t iterator=scratch+0x20;initialize_iterator(m,iterator,4);
            if(h2_network_connection_next_component(m,connection,iterator)) {
                uint32_t sequence=h2_read32(m,scratch+8);
                do {
                    invoke(m,c,h2_read32(m,iterator+16),0x18,1,sequence,0,0);
                } while(h2_network_connection_next_component(m,connection,iterator));
            }
        } else if(kind==1 || kind==2 || kind==3) {
            *h2_ptr(m,scratch+12,1)=kind!=3;
            uint32_t iterator=scratch+0x34;initialize_iterator(m,iterator,8);
            uint8_t available=h2_network_connection_next_component(m,connection,iterator);
            uint32_t success=h2_read32(m,scratch+12);
            if(available) {
                uint32_t sequence=h2_read32(m,scratch+8);
                do {
                    invoke(m,c,h2_read32(m,iterator+16),0x1c,2,sequence,success,0);
                } while(h2_network_connection_next_component(m,connection,iterator));
            }
            if(h2_read32(m,connection+0x40)) {
                *h2_ptr(m,scratch,1)=0;
                if(!*h2_ptr(m,scratch+12,1)) *h2_ptr(m,scratch,1)=1;
                else {
                    uint32_t saved_stream=h2_read32(m,scratch+0x14),bits=h2_read32(m,0x4cf728);
                    float factor;memcpy(&factor,&bits,4);
                    volatile float base=(float)sv(h2_read32(m,saved_stream+0x968));
                    volatile float product=base*factor;
                    float value=product;memcpy(&bits,&value,4);h2_write32(m,scratch+0x18,bits);
                    double rounded=nearbyint((double)value);
                    uint32_t converted=!isfinite(rounded)||rounded < -2147483648.0||rounded > 2147483647.0 ? UINT32_C(0x80000000) : (uint32_t)(int64_t)rounded;
                    h2_write32(m,scratch+0x1c,converted);
                    uint32_t threshold=h2_read32(m,saved_stream+0x968)+h2_read32(m,0x4cf72c);
                    if(sv(converted)>sv(threshold)) threshold=converted;
                    if(sv(h2_read32(m,scratch+4))>=sv(threshold)) *h2_ptr(m,scratch,1)=1;
                }
                uint32_t object=h2_read32(m,connection+0x40);
                invoke(m,c,object,12,3,h2_read32(m,connection+0x44),success,h2_read32(m,scratch));
            }
        }
        kind=h2_network_stream_poll_event(m,clock,h2_read32(m,scratch+0x14),scratch+8,scratch+16,scratch+4,scratch+72);
    }
}
