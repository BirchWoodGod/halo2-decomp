#include "halo2/network_game_members.h"
#include "internal/memory.h"
uint32_t h2_network_game_matching_members(h2_memory *m,uint32_t scratch) {
    if(!*h2_ptr(m,0x4c99b8,1)||!*h2_ptr(m,0x476fcc,1)) return 0;
    uint32_t description=h2_network_game_description(m,scratch);
    if(!description || description+0x10d4u==0) return 0;
    uint32_t mask=h2_network_game_member_mask(m,scratch),id=h2_network_game_selected_id(m,scratch),result=0;
    for(uint32_t i=0;i<16;++i) {
        uint32_t bit=1u<<i;
        if((mask&bit) && h2_read32(m,description+0x10e0+i*0x13c)==id) result|=bit;
    }
    return result;
}
uint32_t h2_network_game_member_value(h2_memory *m,uint32_t table,uint32_t index,uint32_t scratch) {
    if(!*h2_ptr(m,table,1)) return 0;
    uint32_t mask=h2_network_game_matching_members(m,scratch);
    return (mask&(1u<<(index&31))) ? h2_read32(m,table+index*4+4) : 0;
}
