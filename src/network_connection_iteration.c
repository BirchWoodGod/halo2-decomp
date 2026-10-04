#include "halo2/network_connection_iteration.h"
#include "internal/memory.h"
static int64_t signed32(uint32_t value) {
    return value&UINT32_C(0x80000000) ? (int64_t)value-INT64_C(0x100000000) : value;
}
uint8_t h2_network_connection_next_component(h2_memory *m,uint32_t connection,uint32_t iterator) {
    uint32_t cursor=h2_read32(m,iterator+4),combined=h2_read32(m,iterator+8),entry=0;
    for(;;) {
        int first=cursor==UINT32_MAX;
        if(first) {cursor=0;combined=0;}
        if(!(cursor&UINT32_C(0x80000000))) {
            uint32_t index=cursor&UINT32_C(0x7fffffff);
            if(!first) {++index;cursor=index&UINT32_C(0x7fffffff);combined=index;}
            if(signed32(index)<0 || signed32(index)>=signed32(h2_read32(m,connection+0x20))) {
                combined=h2_read32(m,connection+0x20);cursor=UINT32_C(0x80000000);first=1;
            } else entry=connection+0x24+index*8;
        }
        if(cursor&UINT32_C(0x80000000)) {
            uint32_t index=cursor&UINT32_C(0x7fffffff);
            if(!first) {combined=h2_read32(m,connection+0x20);++index;cursor=index|UINT32_C(0x80000000);combined+=index;}
            uint32_t provider=h2_read32(m,connection+0x3c);
            uint32_t count=provider ? h2_read32(m,provider+12) : 0;
            if(signed32(index)<0 || signed32(index)>=signed32(count)) {
                cursor=UINT32_MAX;combined=UINT32_MAX;break;
            }
            entry=provider+16+index*8;
        }
        uint32_t required=h2_read32(m,iterator);
        if((h2_read32(m,entry)&required)==required) break;
    }
    h2_write32(m,iterator+4,cursor);h2_write32(m,iterator+8,combined);
    if(cursor==UINT32_MAX) {
        h2_write32(m,iterator+16,0);h2_write32(m,iterator+12,0);return 0;
    }
    h2_write32(m,iterator+16,h2_read32(m,entry+4));
    h2_write32(m,iterator+12,h2_read32(m,entry));
    return 1;
}
void h2_network_connection_stamp(h2_memory *m,const h2_network_state_operations *c,uint32_t connection,uint32_t slot) {
    uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);
    h2_write32(m,connection+0x98+(slot<<4),now);
    h2_write32(m,connection+((slot+10)<<4),h2_read32(m,0x4e6398));
    h2_write32(m,connection+((slot+10)<<4)+4,h2_read32(m,0x4e639c));
}
