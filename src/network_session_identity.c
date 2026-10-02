#include "halo2/network_session_identity.h"
#include "internal/memory.h"
static uint16_t read16(h2_memory *m,uint32_t p) {
    const uint8_t *b=h2_ptr(m,p,2);return (uint16_t)(b[0]|(uint16_t)b[1]<<8);
}
uint32_t h2_network_session_find_machine(h2_memory *m,uint32_t session,uint32_t identity,uint32_t scratch) {
    if (!h2_read32(m,session+0x741c) || h2_read32(m,session+0x4c)==UINT32_MAX) return UINT32_MAX;
    uint32_t count=h2_read32(m,session+0x54);
    if (count&0x80000000u) return UINT32_MAX;
    for (uint32_t i=0;i<count;++i) {
        uint32_t record=session+0x62+i*0x10c;
        uint32_t first=h2_read32(m,record);uint16_t last=read16(m,record+4);
        h2_write32(m,scratch,first);uint8_t *b=h2_ptr(m,scratch+4,2);b[0]=(uint8_t)last;b[1]=(uint8_t)(last>>8);
        uint32_t j=0;
        for (;j<3;++j) if (read16(m,scratch+j*2)!=read16(m,identity+j*2)) break;
        if (j==3) return i;
    }
    return UINT32_MAX;
}
uint32_t h2_network_session_find_player(h2_memory *m,uint32_t session,uint32_t identity) {
    if (!h2_read32(m,session+0x741c) || h2_read32(m,session+0x4c)==UINT32_MAX) return UINT32_MAX;
    uint32_t mask=h2_read32(m,session+0x111c);
    for (uint32_t i=0;i<16;++i) {
        if (!(mask&(UINT32_C(1)<<i))) continue;
        uint32_t j=0;
        for (;j<3;++j) if (h2_read32(m,identity+j*4)!=h2_read32(m,session+0x1120+i*0x13c+j*4)) break;
        if (j==3) return i;
    }
    return UINT32_MAX;
}
uint8_t h2_network_session_queue_identity(h2_memory *m,const h2_network_state_operations *clock,uint32_t session,uint32_t identity,uint32_t owner,uint32_t value,uint32_t argument) {
    uint32_t entry=session+0x7668,end=session+0x78a8;
    for (;entry<end;entry+=36) if (!*h2_ptr(m,entry,1)) break;
    if (entry>=end) return 0;
    for (uint32_t i=0;i<3;++i) h2_write32(m,entry+10+i*4,h2_read32(m,identity+i*4));
    uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,entry+0x1c,now);h2_write32(m,entry+0x20,value);
    h2_write32(m,entry+2,h2_read32(m,owner));h2_write32(m,entry+6,h2_read32(m,owner+4));
    h2_write32(m,entry+0x18,argument);*h2_ptr(m,entry,1)=1;
    *h2_ptr(m,entry+1,1)=h2_network_session_find_player(m,session,entry+10)!=UINT32_MAX;
    return 1;
}
