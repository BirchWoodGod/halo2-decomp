#include "halo2/network_observer_request.h"
#include "halo2/network_accept_helpers.h"
#include "internal/memory.h"
static int above_two(uint32_t v) { return v>2 && v<UINT32_C(0x80000000); }
void h2_network_observer_handle_request(h2_memory *m,const h2_observer_request_context *c,uint32_t observer,uint32_t address,uint32_t request) {
    const h2_connection_accept_context *a=c->accept;
    uint32_t local=c->local88,reason=4;
    if(h2_network_address_query(m,c->query,address,c->query4)==2) {
        reason=1;
        uint8_t *width=h2_ptr(m,address+0x12,2);
        if(!((width[0]|(uint32_t)width[1]<<8)==4 && h2_read32(m,address)==0x7f000001)) {
            uint32_t flags=h2_read32(m,request+4);
            if(!(flags&0xc0)) {
                uint32_t converted=((flags>>1)&1)|((flags&1)<<1)|(flags&0x3c);
                if(h2_network_connection_flags_valid(converted)) {
                    reason=3;
                    if(h2_network_identity_resolve(m,c->identity,address,0,local+12,local+4,local+16,local+64)) {
                        h2_write32(m,local,0);
                        for(uint32_t index=0;index<15;index++) {
                            uint32_t entry=observer+0xa8+index*0x528;
                            if(!h2_read32(m,entry)) continue;
                            uint32_t word=0;
                            while(word<9 && h2_read32(m,local+64+word*4)==h2_read32(m,entry+0x14+word*4)) word++;
                            if(word!=9 || !*h2_ptr(m,entry+9,1)) continue;
                            uint32_t connection=h2_read32(m,0x4d87d4)+h2_read32(m,entry+12)*0xf8;
                            h2_write32(m,local,index);
                            h2_network_connection_copy_address(m,connection,local+36);
                            uint32_t difference=h2_read32(m,request)-h2_read32(m,connection+0x50);
                            if(above_two(h2_read32(m,connection+0x54))) {
                                uint8_t close=0;
                                if(!h2_network_address_equal(m,address,local+36,0)) {
                                    h2_network_identity_resolve(m,c->identity,local+36,0,local+32,local+56,0,local+100);
                                    h2_network_address_query(m,c->query,local+36,c->query4);
                                    close=1;
                                } else if(h2_read32(m,connection+0x50)!=UINT32_MAX && difference) close=1;
                                if(close) h2_network_connection_close(m,a->clock,a->send,a->codec,c->callbacks,connection,6,c->close16,a->packet,a->workspace28);
                            }
                            if(!above_two(h2_read32(m,connection+0x54))) {
                                h2_network_address_prepare(m,c->resolution,address,c->prepare4);
                                for(uint32_t i=0;i<20;i+=4) h2_write32(m,entry+0x5c+i,h2_read32(m,address+i));
                                uint32_t id=h2_read32(m,local+12),key0=h2_read32(m,local+4),key1=h2_read32(m,local+8);
                                h2_write32(m,entry+0x40,id);h2_write32(m,entry+0x44,key0);
                                uint32_t v=h2_read32(m,local+16);h2_write32(m,entry+0x48,key1);
                                uint32_t next=h2_read32(m,local+20);h2_write32(m,entry+0x4c,v);
                                v=h2_read32(m,local+24);h2_write32(m,entry+0x50,next);
                                next=h2_read32(m,local+28);h2_write32(m,entry+0x54,v);h2_write32(m,entry+0x58,next);
                                h2_write32(m,entry+0x3c,UINT32_MAX);
                                h2_network_connection_open(m,a->clock,a->send,a->codec,c->callbacks,c->storage,connection,address,0,c->open_message8,c->close16,c->storage8,a->packet,a->workspace28);
                                h2_network_observer_set_state(m,a->clock,c->events,observer,index,6);
                                uint8_t *retry=h2_ptr(m,entry+10,2);retry[0]=0;retry[1]=0;
                                h2_network_observer_update_slot(m,a->clock,a->send,a->codec,c->callbacks,c->registration,c->events,observer,index,c->close16,a->packet,a->workspace28);
                            }
                            h2_network_connection_accept(m,a,connection,h2_read32(m,request));
                            h2_network_observer_refresh_address(m,c->query,a->clock,a->send,a->codec,c->callbacks,c->registration,c->events,observer,index,c->query4,c->close16,a->packet,a->workspace28);
                            h2_network_observer_update_slot(m,a->clock,a->send,a->codec,c->callbacks,c->registration,c->events,observer,index,c->close16,a->packet,a->workspace28);
                            return;
                        }
                        h2_write32(m,local,15);
                    }
                }
            }
        }
    }
    uint32_t remote=h2_read32(m,request);
    h2_write32(m,local+8,reason);h2_write32(m,local+4,remote);
    h2_message_writer_enqueue(m,a->clock,a->send,a->codec,h2_read32(m,observer+8),address,5,8,local+4,a->packet,a->workspace28);
}
