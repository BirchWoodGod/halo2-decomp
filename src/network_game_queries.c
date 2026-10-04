#include "halo2/network_game_queries.h"
#include "internal/memory.h"
static uint8_t enabled(h2_memory *m) {return *h2_ptr(m,0x4c99b8,1)&&*h2_ptr(m,0x476fcc,1);}
uint32_t h2_network_game_description(h2_memory *m,uint32_t scratch) {
    if(!enabled(m)) return 0;
    h2_write32(m,scratch,0);
    if(!h2_network_game_session_selected(m,scratch)) return 0;
    uint32_t p=h2_read32(m,scratch);
    if(!h2_read32(m,p+0x741c)||h2_read32(m,p+0x4c)==UINT32_MAX) return 0;
    return p+0x4c;
}
uint32_t h2_network_game_selected_id(h2_memory *m,uint32_t scratch) {
    if(!enabled(m)) return UINT32_MAX;
    h2_write32(m,scratch,0);
    if(!h2_network_game_session_selected(m,scratch)) return UINT32_MAX;
    uint32_t p=h2_read32(m,scratch);
    if(!h2_read32(m,p+0x741c)||h2_read32(m,p+0x4c)==UINT32_MAX) return UINT32_MAX;
    return h2_read32(m,p+0x72d8);
}
uint32_t h2_network_game_member_mask(h2_memory *m,uint32_t scratch) {
    if(!enabled(m)) return 0;
    uint32_t p=h2_network_game_description(m,scratch);
    return p ? h2_read32(m,p+0x10d0) : 0;
}
uint8_t h2_network_game_id_matches(h2_memory *m,uint32_t scratch) {
    if(!enabled(m)) return 0;
    uint32_t id=h2_network_game_selected_id(m,scratch);
    if(id==UINT32_MAX) return 0;
    uint32_t current=enabled(m) ? h2_read32(m,0x4c9878) : 0;
    return id==current;
}
uint32_t h2_network_game_member_flags(h2_memory *m,uint32_t index,uint32_t scratch) {
    if(!enabled(m)) return 0;
    uint32_t p=h2_network_game_description(m,scratch),mask=p ? h2_read32(m,p+0x10d0) : 0;
    if(!(mask&(1u<<(index&31)))) return 0;
    const uint8_t *v=h2_ptr(m,0x4c9988+index*2,2);return v[0]|((uint32_t)v[1]<<8);
}
uint8_t h2_network_game_member_flag2(h2_memory *m,uint32_t index,uint32_t scratch) {
    if(!enabled(m)) return 0;
    return (h2_network_game_member_flags(m,index,scratch)>>2)&1;
}
