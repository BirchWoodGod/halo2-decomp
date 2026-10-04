#include "halo2/network_game_activity.h"
#include "internal/memory.h"
static uint8_t enabled(h2_memory *m) {return *h2_ptr(m,0x4c99b8,1)&&*h2_ptr(m,0x476fcc,1);}
uint8_t h2_network_game_peer_active(h2_memory *m,uint32_t peer,uint32_t scratch) {
    if(!enabled(m)) return 0;
    uint32_t description=h2_network_game_description(m,scratch);
    if(!description || description+0x10d4u==0) return 0;
    if(h2_network_game_id_matches(m,scratch)) return 1;
    uint32_t members=h2_network_game_matching_members(m,scratch);
    for(uint32_t i=0;i<16;++i) {
        if(!(members&(1u<<i))) continue;
        if(enabled(m) && (h2_network_game_member_flags(m,i,scratch)&2)) continue;
        if(h2_network_game_member_flag2(m,i,scratch)) continue;
        uint32_t selected=h2_network_game_member_value(m,0x5259b8,i,scratch);
        if(!selected) continue;
        h2_write32(m,scratch+24,0);
        h2_network_game_member_routes(m,selected,0x527104,scratch+24,scratch);
        const uint8_t *p=h2_ptr(m,scratch+24,2);
        uint32_t routes=p[0]|((uint32_t)p[1]<<8);
        if(routes&(1u<<(peer&31))) return 1;
    }
    return 0;
}
