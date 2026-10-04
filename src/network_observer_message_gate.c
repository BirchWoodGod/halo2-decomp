#include "halo2/network_observer_message_gate.h"
#include "internal/memory.h"
static uint64_t bit(uint32_t type) {
    uint32_t shift=(uint8_t)type;return shift>=64 ? 0 : UINT64_C(1)<<shift;
}
uint8_t h2_network_observer_message_deferred(h2_memory *m,uint32_t observer,uint32_t index,uint32_t type) {
    uint32_t entry=observer+0xa8+index*0x528,id=h2_read32(m,entry+12);
    if(id==UINT32_MAX) return 0;
    uint32_t connection=h2_read32(m,0x4d87d4)+id*0xf8;
    if(h2_read32(m,connection+0x54)!=5) return 0;
    uint64_t mask=bit(type);
    uint32_t limit=((h2_read32(m,entry+0x520)&(uint32_t)mask) ||
        (h2_read32(m,entry+0x524)&(uint32_t)(mask>>32))) ? 0xc000 : 0x4000;
    uint32_t value=h2_network_connection_send_capacity(m,connection)*4;
    return (value&UINT32_C(0x80000000)) || value<limit;
}
void h2_network_observer_defer_message(h2_memory *m,uint32_t observer,uint32_t index,uint32_t type) {
    uint32_t entry=observer+0xa8+index*0x528,id=h2_read32(m,entry+12);
    if(id==UINT32_MAX) return;
    uint32_t connection=h2_read32(m,0x4d87d4)+id*0xf8;
    if(h2_read32(m,connection+0x54)!=5) return;
    uint64_t mask=bit(type);uint32_t low=h2_read32(m,entry+0x520),high=h2_read32(m,entry+0x524);
    if(!(low&(uint32_t)mask) && !(high&(uint32_t)(mask>>32))) {
        h2_write32(m,entry+0x520,low|(uint32_t)mask);
        h2_write32(m,entry+0x524,high|(uint32_t)(mask>>32));
    }
}
