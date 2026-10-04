#include "halo2/network_replication_changes.h"
#include "internal/memory.h"
static uint32_t word(h2_memory *m,uint32_t address) {
    const uint8_t *p=h2_ptr(m,address,2);
    return p[0]|((uint32_t)p[1]<<8);
}
void h2_network_replication_mark_changes(h2_memory *m,uint32_t manager,uint32_t handle,uint32_t mask) {
    uint32_t index=handle&0x3ff;
    for(uint32_t i=0;i<15;++i) {
        uint32_t peer=h2_read32(m,manager+4+i*4);
        if(!peer) continue;
        uint32_t record=peer+0x24+index*0x14;
        if(word(m,record+8)==3) {
            uint32_t flags=word(m,h2_read32(m,peer+0x14)+0x46+index*8);
            uint32_t bit=UINT32_C(1)<<(h2_read32(m,peer+12)&31);
            if(!(flags&bit) && !h2_read32(m,record+4))
                h2_write32(m,peer+0x5034,h2_read32(m,peer+0x5034)+1);
        }
        h2_write32(m,record+4,h2_read32(m,record+4)|mask);
    }
}
void h2_network_replication_flush_changes(h2_memory *m,const h2_replication_change_callbacks *c,uint32_t table,uint32_t scratch) {
    for(uint32_t i=0;i<1024;++i) {
        uint32_t record=table+0x14+i*0x20;
        if(h2_read32(m,record)==UINT32_MAX) continue;
        uint32_t mask=h2_read32(m,record+12);
        if(!mask) continue;
        if(*h2_ptr(m,record+6,1)) {
            uint32_t type=word(m,record+4);
            if(type&0x8000) type|=UINT32_C(0xffff0000);
            uint32_t object=h2_read32(m,h2_read32(m,table+16)+4+type*4);
            uint32_t argument2=h2_read32(m,record+28);
            uint32_t argument1=h2_read32(m,record+24);
            h2_write32(m,scratch,mask);
            uint32_t function=h2_read32(m,h2_read32(m,object)+0x50);
            if(c->filter(c->context,function,object,record,scratch,argument1,argument2)) {
                mask=h2_read32(m,scratch);
                if(mask) {
                    uint32_t handle=h2_read32(m,record);
                    h2_network_replication_mark_changes(m,h2_read32(m,table+12),handle,mask);
                }
            }
        }
        h2_write32(m,record+12,0);
    }
}
