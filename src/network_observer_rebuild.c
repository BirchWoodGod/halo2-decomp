#include "halo2/network_observer_rebuild.h"
#include "internal/memory.h"
void h2_network_observer_rebuild_connections(h2_memory *m,const h2_observer_rebuild_context *c,uint32_t observer) {
    const h2_observer_tick_context *t=c->tick;
    uint32_t local=c->local12c;
    h2_write32(m,local,0);
    for(uint32_t index=0;index<15;index++) {
        uint32_t entry=observer+0xa8+index*0x528;
        if(h2_read32(m,entry)) {
            for(uint32_t i=0;i<36;i+=4) h2_write32(m,local+8+i,h2_read32(m,entry+0x14+i));
            uint32_t ip=h2_read32(m,local+8);
            uint32_t swapped=(ip>>24)|((ip>>8)&0xff00)|((ip<<8)&0xff0000)|(ip<<24);
            h2_write32(m,local+4,swapped);
            for(uint32_t i=0;i<4;i++) h2_write32(m,c->arguments16+i*4,(ip>>(i*8))&255);
            h2_text_format(m,c->format,local+0x2c,256,0x450c38,c->arguments16);
            uint32_t connection=h2_network_connection_allocate(m,t->clock,t->send,t->codec,t->connections,t->storage,local+0x2c,0x38,t->detach16,t->packet,t->storage8,t->workspace28);
            h2_write32(m,entry+12,connection);
            if(connection!=UINT32_MAX) h2_write32(m,h2_read32(m,0x4d87d4)+connection*0xf8+0x40,observer);
            h2_network_observer_refresh_address(m,t->query,t->clock,t->send,t->codec,t->connections,t->registration,t->events,observer,index,t->query4,t->detach16,t->packet,t->workspace28);
            h2_network_observer_update_slot(m,t->clock,t->send,t->codec,t->connections,t->registration,t->events,observer,index,t->detach16,t->packet,t->workspace28);
            h2_network_observer_tick(m,t,observer,index);
        }
        h2_write32(m,local,index+1);
    }
}
