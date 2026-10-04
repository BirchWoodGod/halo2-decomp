#include "halo2/network_connection_update.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static void iterator(h2_memory *m,uint32_t p,uint32_t flags) {
    h2_write32(m,p+12,0);h2_write32(m,p+16,0);h2_write32(m,p,flags);
    h2_write32(m,p+4,UINT32_MAX);h2_write32(m,p+8,UINT32_MAX);
}
static uint32_t invoke(h2_memory *m,const h2_connection_update_context *c,
    uint32_t object,uint32_t slot,uint32_t count,const uint32_t *args) {
    uint32_t function=h2_read32(m,h2_read32(m,object)+slot);
    return c->update->invoke(c->update->context,function,object,count,args);
}
static void close_connection(h2_memory *m,const h2_connection_update_context *c,
    uint32_t connection,uint32_t reason,uint32_t scratch,uint8_t workspace[28]) {
    h2_network_connection_close(m,c->clock,c->send,c->codec,c->close,connection,
        reason,scratch+0x283c,scratch+0x2848,workspace);
}
void h2_network_connection_update(h2_memory *m,const h2_connection_update_context *c,
    uint32_t connection,uint32_t scratch,uint8_t workspace[28]) {
    if(h2_read32(m,connection+0x54)==3 && *h2_ptr(m,connection+0x84,1))
        h2_network_connection_update_handshake(m,c->clock,c->send,c->codec,c->close,
            connection,scratch+0x2834,scratch+0x283c,scratch+0x2848,workspace);
    if(h2_read32(m,connection+0x54)==4) {
        uint32_t previous=h2_read32(m,connection+0x94);
        uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->clock->ticks(c->clock->context);
        uint32_t config=h2_read32(m,connection+12);
        if(sv(now-previous)>sv(h2_read32(m,config+12))) close_connection(m,c,connection,7,scratch,workspace);
    }
    uint32_t it=scratch+0x14;
    if(sv(h2_read32(m,connection+0x54))>=4) {
        iterator(m,it,16);
        while(h2_network_connection_next_component(m,connection,it)) {
            uint32_t argument=scratch+4;h2_write32(m,argument,0);
            if((uint8_t)invoke(m,c,h2_read32(m,it+16),4,1,&argument)) {
                close_connection(m,c,connection,h2_read32(m,scratch+4),scratch,workspace);break;
            }
        }
    }
    if(sv(h2_read32(m,connection+0x54))>=4) {
        *h2_ptr(m,scratch+16,1)=0;*h2_ptr(m,scratch+12,1)=0;*h2_ptr(m,scratch+8,1)=0;
        uint32_t provider=h2_read32(m,connection+0x3c);
        uint32_t flags=!(provider && *h2_ptr(m,provider+0x31,1));iterator(m,it,flags);
        while(h2_network_connection_next_component(m,connection,it)) {
            uint32_t argument=scratch+3;*h2_ptr(m,argument,1)=0;
            if((uint8_t)invoke(m,c,h2_read32(m,it+16),8,1,&argument)) {
                *h2_ptr(m,scratch+(h2_read32(m,it+12)&32 ? 12 : 16),1)=1;
                if(*h2_ptr(m,scratch+3,1)) *h2_ptr(m,scratch+8,1)=1;
            }
        }
        if(!(*h2_ptr(m,connection+0x48,1)&8) && *h2_ptr(m,scratch+8,1)) *h2_ptr(m,scratch+8,1)=0;
        uint32_t observer=h2_read32(m,connection+0x40),secondary_size;
        uint8_t send;
        if(observer) {
            uint32_t args[10]={h2_read32(m,connection+0x44),h2_read32(m,scratch+16),
                h2_read32(m,scratch+12),h2_read32(m,scratch+8),scratch+2,scratch+0x28,
                scratch+0x2c,scratch+4,512,scratch+0x64};
            send=(uint8_t)invoke(m,c,observer,20,10,args);secondary_size=h2_read32(m,scratch+4);
        } else {
            send=!!(*h2_ptr(m,scratch+16,1)||*h2_ptr(m,scratch+12,1));
            *h2_ptr(m,scratch+2,1)=*h2_ptr(m,scratch+8,1);
            *h2_ptr(m,scratch+0x28,1)=0;h2_write32(m,scratch+0x2c,1536);
            secondary_size=0;h2_write32(m,scratch+4,0);
        }
        if(send) {
            uint32_t stream=scratch+0x30;
            h2_write32(m,stream+4,h2_read32(m,scratch+0x2c));h2_write32(m,stream,scratch+0x264);
            h2_write32(m,stream+8,1);h2_write32(m,stream+12,0);h2_write32(m,stream+16,0);
            h2_write32(m,stream+24,0);*h2_ptr(m,stream+20,1)=0;
            h2_network_connection_build_packet(m,c->clock,c->send,c->reserve,c->build,
                *h2_ptr(m,scratch+2,1),connection,stream,*h2_ptr(m,scratch+0x28,1),
                secondary_size,sv(secondary_size)>0 ? scratch+0x64 : 0,
                scratch+8,scratch+16,scratch+12,scratch+0x864,workspace);
            h2_network_connection_stamp(m,c->clock,connection,0);
            if(*h2_ptr(m,scratch+2,1)) h2_network_connection_stamp(m,c->clock,connection,1);
            if(sv(h2_read32(m,scratch+4))>0) h2_network_connection_stamp(m,c->clock,connection,2);
        }
    }
    if(sv(h2_read32(m,connection+0x54))>=4)
        h2_network_connection_dispatch_events(m,c->clock,c->events,connection,scratch+0x27e8);
}
void h2_network_endpoint_update(h2_memory *m,const h2_connection_update_context *c,
    uint32_t endpoint,uint32_t scratch,uint8_t workspace[28]) {
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,endpoint+0x20));++i) {
        uint32_t entry=endpoint+0x2c+i*32;
        uint32_t connection=h2_read32(m,0x4d87d4)+h2_read32(m,entry-8)*0xf8;
        h2_network_connection_update(m,c,connection,scratch,workspace);
        if(*h2_ptr(m,entry,1)) {
            if(sv(h2_read32(m,connection+0x54))>2) close_connection(m,c,connection,9,scratch,workspace);
            *h2_ptr(m,entry,1)=0;
        }
    }
}
