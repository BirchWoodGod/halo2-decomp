#include "halo2/game_lifecycle.h"
#include "internal/memory.h"
#include <string.h>
static void write16(h2_memory *m,uint32_t address,uint32_t value) {
    uint8_t *p=h2_ptr(m,address,2);p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
}
static void callbacks(h2_memory *m,const h2_game_operations *ops,unsigned column,int reverse) {
    for (unsigned i=0;i<68;i++) {
        unsigned index=reverse ? 67-i : i;
        uint32_t function=h2_read32(m,0x440dd8+index*36+column*4);
        if (function || column==0) ops->dispatch(ops->context,function);
    }
}
void h2_game_initialize(h2_memory *m,const h2_arena_platform *platform,const h2_game_operations *ops) {
    h2_arena_initialize(m,platform);
    uint32_t state=h2_arena_reserve(m,0x1200);
    memset(h2_ptr(m,state,0x1200),0,0x1200);
    h2_write32(m,0x4e6948,state);
    write16(m,state+2,0xffff);
    ops->control_fp(ops->context,0x9001f,0xfffff);
    callbacks(m,ops,0,0);
}
void h2_game_set_options(h2_memory *m,const h2_game_operations *ops,uint32_t options) {
    uint32_t state=h2_read32(m,0x4e6948);
    for (uint32_t i=0;i<0x1118;i+=4) h2_write32(m,state+8+i,h2_read32(m,options+i));
    uint32_t mode=h2_read32(m,state+8);
    *h2_ptr(m,state+0x12c,1)=0;
    if (mode==2 || h2_read32(m,state+0x180)!=0) {
        ops->validate_variant(ops->context,state+0x13c);
        state=h2_read32(m,0x4e6948);
    }
    h2_write32(m,h2_read32(m,0x4e7408),h2_read32(m,state+0x18));
    *h2_ptr(m,state+0x1121,1)=0;
    *h2_ptr(m,state+0x1128,1)=0;
    write16(m,state+0x11fa,0);
    h2_write32(m,state+0x1130,0);
}
void h2_game_initialize_for_map(h2_memory *m,const h2_game_operations *ops,uint32_t options) {
    ops->control_fp(ops->context,0x9001f,0xfffff);
    *h2_ptr(m,h2_read32(m,0x4e6948),1)=1;
    h2_game_set_options(m,ops,options);
    callbacks(m,ops,2,0);
    uint32_t state=h2_read32(m,0x4e6948);
    *h2_ptr(m,state,1)=0;*h2_ptr(m,state+1,1)=1;
}
void h2_game_dispose_from_map(h2_memory *m,const h2_game_operations *ops) {
    *h2_ptr(m,h2_read32(m,0x4e6948)+0x1120,1)=0;
    callbacks(m,ops,3,1);
    *h2_ptr(m,h2_read32(m,0x4e6948)+1,1)=0;
}
void h2_game_initialize_for_structure(h2_memory *m,const h2_game_operations *ops) {
    uint32_t state=h2_read32(m,0x4e6948);
    memset(h2_ptr(m,state+0x1138,0xc0),0,0xc0);
    const uint8_t *index=h2_ptr(m,0x4686c4,2);
    write16(m,state+2,(uint32_t)index[0]+((uint32_t)index[1]<<8));
    callbacks(m,ops,4,0);
}
void h2_game_dispose_from_structure(h2_memory *m,const h2_game_operations *ops) {
    callbacks(m,ops,5,1);
    write16(m,h2_read32(m,0x4e6948)+2,0xffff);
}
