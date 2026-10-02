#include "halo2/network_observer_admit.h"
#include "halo2/network_endpoint.h"
#include "internal/memory.h"
#include <string.h>
static int64_t signed32(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static float read_float(h2_memory *m,uint32_t address) {float value;memcpy(&value,h2_ptr(m,address,4),4);return value;}
static void write_float(h2_memory *m,uint32_t address,float value) {memcpy(h2_ptr(m,address,4),&value,4);}
static void reset_window(h2_memory *m,uint32_t entry,uint32_t offset,uint32_t count,float numerator) {
    h2_write32(m,entry+offset+0x1c,count);
    float divisor=(float)signed32(count);
    for (uint32_t i=0;i<20;i+=4) h2_write32(m,entry+offset+i,0);
    h2_write32(m,entry+offset+0x20,(uint32_t)(signed32(count)/20));
    write_float(m,entry+offset+0x24,numerator/divisor);
    h2_write32(m,entry+offset+0x14,0);h2_write32(m,entry+offset+0x18,0);
    h2_write32(m,entry+offset+0x28,0);
    memset(h2_ptr(m,entry+offset+0x2c,160),0,160);
    h2_write32(m,entry+offset+0xcc,0);h2_write32(m,entry+offset+0xd0,0);
}
uint32_t h2_network_observer_admit(h2_memory *m,const h2_observer_admit_context *a,uint32_t observer,uint32_t consumer,uint32_t identity) {
    const h2_observer_tick_context *c=a->network;
    uint32_t index=UINT32_MAX,entry=0;
    for (uint32_t i=0;i<15;++i) {
        uint32_t candidate=observer+0xa8+i*0x528;
        if (h2_read32(m,candidate) && !memcmp(h2_ptr(m,identity,36),h2_ptr(m,candidate+0x14,36),36)) {index=i;goto notify;}
    }
    for (uint32_t i=0;i<15;++i) if (!h2_read32(m,observer+0xa8+i*0x528)) {index=i;break;}
    if (index==UINT32_MAX) {
        for (uint32_t i=0;i<15;++i) {
            uint32_t candidate=observer+0xa8+i*0x528;
            if (h2_read32(m,candidate) && !*h2_ptr(m,candidate+9,1)) {index=i;break;}
        }
        if (index==UINT32_MAX) return UINT32_MAX;
        h2_network_observer_release_slot(m,c->clock,c->send,c->codec,c->connections,c->registration,c->storage,a->async,observer,index,c->detach16,c->packet,c->storage8,c->workspace28);
    }
    entry=observer+0xa8+index*0x528;
    for (uint32_t i=0;i<36;i+=4) h2_write32(m,a->identity36+i,h2_read32(m,identity+i));
    uint32_t ip=h2_read32(m,a->identity36);
    for (uint32_t i=0;i<4;++i) h2_write32(m,a->arguments24+i*4,(ip>>(i*8))&255);
    h2_text_format(m,a->format,a->label256,256,0x450c38,a->arguments24);
    for (uint32_t i=0;i<6;++i) h2_write32(m,a->arguments24+i*4,*h2_ptr(m,a->identity36+10+i,1));
    h2_text_append_format(m,a->format,a->label256,256,0x450c14,a->arguments24);
    uint32_t connection_index=h2_network_connection_allocate(m,c->clock,c->send,c->codec,c->connections,c->storage,a->label256,0x38,c->detach16,c->packet,c->storage8,c->workspace28);
    if (connection_index==UINT32_MAX) return UINT32_MAX;
    uint32_t base=h2_read32(m,0x4d87d4);
    h2_write32(m,entry+12,connection_index);h2_write32(m,base+connection_index*0xf8+0x40,observer);
    uint8_t overridden=*h2_ptr(m,0x510548,1);
    h2_write32(m,entry,2);
    uint32_t now=overridden ? h2_read32(m,0x51054c) : c->clock->ticks(c->clock->context);
    h2_write32(m,entry+4,now);
    overridden=*h2_ptr(m,0x510548,1);
    h2_write32(m,entry+0x10,UINT32_MAX);
    for (uint32_t i=0;i<36;i+=4) h2_write32(m,entry+0x14+i,h2_read32(m,identity+i));
    now=overridden ? h2_read32(m,0x51054c) : c->clock->ticks(c->clock->context);
    h2_write32(m,entry+0x94,now);h2_write32(m,entry+0x98,0);h2_write32(m,entry+0x9c,0);
    uint32_t count=h2_read32(m,h2_read32(m,observer+16)+0xf8);
    float numerator=read_float(m,0x45dccc);
    reset_window(m,entry,0xa0,count,numerator);
    count=h2_read32(m,h2_read32(m,observer+16)+0xf8);
    reset_window(m,entry,0x178,count,numerator);
    h2_write32(m,entry+0x250,h2_read32(m,h2_read32(m,observer+16)+0xfc));
    h2_network_samples_reset(m,c->clock,entry+0x250);
    h2_write32(m,entry+0x360,h2_read32(m,h2_read32(m,observer+16)+0xfc));
    h2_network_samples_reset(m,c->clock,entry+0x360);
    *h2_ptr(m,entry+10,1)=0;*h2_ptr(m,entry+11,1)=0;
    h2_write32(m,entry+0x38,0);h2_write32(m,entry+0x3c,UINT32_MAX);
    h2_network_observer_detach(m,c->clock,c->send,c->codec,c->connections,c->registration,observer,index,0,0,c->detach16,c->packet,c->workspace28);
notify:
    entry=observer+0xa8+index*0x528;
    uint8_t mask=*h2_ptr(m,entry+9,1),flags=*h2_ptr(m,entry+8,1);
    *h2_ptr(m,entry+9,1)=mask|(uint8_t)(UINT32_C(1)<<(consumer&31));
    if (flags&2) {
        uint32_t identifier=h2_read32(m,entry+0x10),object=h2_read32(m,observer+0x14+consumer*36);
        uint32_t function=h2_read32(m,h2_read32(m,object)+12);
        c->events->connection(c->events->context,function,object,index,identifier,1);
    }
    return index;
}
