#include "halo2/network_session_membership.h"
#include "internal/memory.h"
static void write16(h2_memory *m,uint32_t p,uint16_t v) {
    uint8_t *b=h2_ptr(m,p,2);b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);
}
static void copy_name(h2_memory *m,uint32_t destination,uint32_t count) {
    uint32_t source=0x450aac;uint16_t word=1;
    for (uint32_t i=0;i<count;++i) {
        if (word) {const uint8_t *b=h2_ptr(m,source,2);word=(uint16_t)(b[0]|(uint16_t)b[1]<<8);source+=2;}
        write16(m,destination+i*2,word);
    }
    write16(m,destination+count*2,0);
}
void h2_network_session_attach_peer(h2_memory *m,const h2_network_state_operations *clock,uint32_t session,uint32_t index,uint8_t active,uint32_t observer_index) {
    uint32_t peer=session+0x72dc+index*20;
    for (uint32_t i=0;i<5;++i) h2_write32(m,peer+i*4,0);
    h2_write32(m,peer+4,observer_index);*h2_ptr(m,peer,1)=1;*h2_ptr(m,peer+1,1)=active;
    h2_write32(m,peer+8,UINT32_MAX);h2_write32(m,peer+12,UINT32_MAX);*h2_ptr(m,peer+3,1)=0;
    if (active && *h2_ptr(m,session+0x765c,1)) *h2_ptr(m,peer+2,1)=1;
    uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,peer+16,now);
}
void h2_network_session_add_peer(h2_memory *m,const h2_network_state_operations *clock,uint32_t session,uint32_t index,uint32_t identity,uint8_t active,uint32_t observer_index,uint32_t extra) {
    uint32_t peer=session+0x58+index*0x10c;
    h2_write32(m,session+0x54,h2_read32(m,session+0x54)+1);
    for (uint32_t i=0;i<0x43;++i) h2_write32(m,peer+i*4,0);
    copy_name(m,peer+0x28,15);copy_name(m,peer+0x48,31);
    h2_write32(m,peer+0x88,0);h2_write32(m,peer+0x8c,0);
    for (uint32_t i=0;i<4;++i) h2_write32(m,peer+0xfc+i*4,UINT32_MAX);
    for (uint32_t i=0;i<3;++i) h2_write32(m,peer+0x90+i*4,0);
    for (uint32_t i=0;i<17;++i) h2_write32(m,peer+0xac+i*4,0);
    for (uint32_t i=0;i<9;++i) h2_write32(m,peer+i*4,h2_read32(m,identity+i*4));
    if (extra) {h2_write32(m,peer+0xf0,h2_read32(m,extra));h2_write32(m,peer+0xf4,h2_read32(m,extra+4));}
    h2_network_session_attach_peer(m,clock,session,index,active,observer_index);
}
