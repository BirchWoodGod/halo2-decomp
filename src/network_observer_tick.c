#include "halo2/network_observer_tick.h"
#include "halo2/network_observer_retry.h"
#include "internal/memory.h"
static int64_t signed32(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static void clear_retry(h2_memory *m,uint32_t entry) {
    uint8_t *p=h2_ptr(m,entry+10,2);p[0]=0;p[1]=0;
}
static void state(h2_memory *m,const h2_observer_tick_context *c,uint32_t observer,uint32_t index,uint32_t value) {
    h2_network_observer_set_state(m,c->clock,c->events,observer,index,value);
}
static void detach(h2_memory *m,const h2_observer_tick_context *c,uint32_t observer,uint32_t index) {
    h2_network_observer_detach(m,c->clock,c->send,c->codec,c->connections,c->registration,observer,index,0,0,c->detach16,c->packet,c->workspace28);
}
static void refresh(h2_memory *m,const h2_observer_tick_context *c,uint32_t observer,uint32_t index) {
    h2_network_observer_refresh_address(m,c->query,c->clock,c->send,c->codec,c->connections,c->registration,c->events,observer,index,c->query4,c->detach16,c->packet,c->workspace28);
}
static void update_slot(h2_memory *m,const h2_observer_tick_context *c,uint32_t observer,uint32_t index) {
    h2_network_observer_update_slot(m,c->clock,c->send,c->codec,c->connections,c->registration,c->events,observer,index,c->detach16,c->packet,c->workspace28);
}
void h2_network_observer_tick(h2_memory *m,const h2_observer_tick_context *c,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528,current=h2_read32(m,entry);
    if (!current) return;
    uint32_t identifier=h2_read32(m,entry+12);
    if (identifier==UINT32_MAX) return;
    uint32_t connection=h2_read32(m,0x4d87d4)+identifier*0xf8;
    if (current==1) {
        uint32_t elapsed=h2_network_elapsed(m,c->clock,h2_read32(m,entry+4));
        uint32_t config=h2_read32(m,observer+16);
        if (signed32(elapsed)>=signed32(h2_read32(m,config+0x6c))) {
            state(m,c,observer,index,2);clear_retry(m,entry);
            h2_write32(m,entry+0x38,0);h2_write32(m,entry+0x3c,UINT32_MAX);
            detach(m,c,observer,index);refresh(m,c,observer,index);update_slot(m,c,observer,index);
            h2_network_observer_tick(m,c,observer,index);
        }
    }
    if (h2_read32(m,entry)==4 && (*h2_ptr(m,entry+8,1)&1)) {
        state(m,c,observer,index,5);clear_retry(m,entry);
    }
    current=h2_read32(m,entry);
    if (current!=2 && current!=5 && current!=9) return;
    uint32_t config=h2_read32(m,observer+16);
    uint32_t offset=current==2 ? 0 : (*h2_ptr(m,entry+8,1)&4) ? 0x48 : 0x24;
    uint32_t count=h2_read32(m,config+offset),schedule=config+offset+4;
    uint8_t *word=h2_ptr(m,entry+10,2);
    if ((word[0]|(uint32_t)word[1]<<8) || (*h2_ptr(m,entry+8,1)&4)) {
        uint8_t accepted=0;
        for (uint32_t i=0;i<4;++i) {
            if (!(*h2_ptr(m,entry+9,1)&(UINT32_C(1)<<i))) continue;
            uint32_t object=h2_read32(m,observer+0x14+i*36);
            uint32_t function=h2_read32(m,h2_read32(m,object)+8);
            uint32_t reconnect=(*h2_ptr(m,entry+8,1)>>2)&1;
            if (c->request(c->context,function,object,index,reconnect)) accepted=1;
        }
        if (!accepted) {
            if (h2_network_observer_retry_allowed(m,c->clock,c->send,c->codec,c->connections,observer,index,0,c->detach16,c->packet,c->workspace28)) {
                detach(m,c,observer,index);state(m,c,observer,index,1);
            }
            return;
        }
    }
    h2_write32(m,entry+0x98,0);h2_write32(m,entry+0x9c,0);
    word=h2_ptr(m,entry+10,2);
    uint32_t retry=word[0]|(uint32_t)word[1]<<8;
    if ((retry&0x8000) || signed32(retry)>=signed32(count)) {
        detach(m,c,observer,index);state(m,c,observer,index,1);return;
    }
    uint32_t timeout=h2_read32(m,schedule+retry*4);
    if (signed32(h2_network_elapsed(m,c->clock,h2_read32(m,entry+4)))<signed32(timeout)) return;
    if (h2_read32(m,entry)==2) {
        uint8_t selected=h2_network_observer_select_address(m,c->query,c->resolution,c->clock,c->send,c->codec,c->connections,c->registration,observer,index,c->query4,c->detach16,c->resolution28,c->packet,c->workspace28);
        state(m,c,observer,index,selected ? 3 : 1);
    } else {
        h2_network_connection_open(m,c->clock,c->send,c->codec,c->connections,c->storage,connection,entry+0x5c,1,c->message8,c->detach16,c->storage8,c->packet,c->workspace28);
        state(m,c,observer,index,h2_read32(m,entry)==5 ? 6 : 8);
    }
}
void h2_network_observer_request_connection(h2_memory *m,const h2_observer_tick_context *c,uint32_t observer,uint32_t index) {
    uint32_t entry=observer+0xa8+index*0x528;
    if (h2_read32(m,entry+12)==UINT32_MAX) return;
    if (h2_read32(m,entry)==1) {state(m,c,observer,index,2);clear_retry(m,entry);}
    *h2_ptr(m,entry+8,1)|=1;
    refresh(m,c,observer,index);update_slot(m,c,observer,index);
    h2_network_observer_tick(m,c,observer,index);
}
