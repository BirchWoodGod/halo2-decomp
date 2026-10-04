#include "halo2/network_game_route_queries.h"
#include "internal/memory.h"
static uint8_t enabled(h2_memory *m) {return *h2_ptr(m,0x4c99b8,1)&&*h2_ptr(m,0x476fcc,1);}
uint32_t h2_network_game_route_limit(h2_memory *m) {
    if(!enabled(m)) return 0;
    uint32_t mode=h2_read32(m,0x4c9888);
    if(mode==1) return h2_read32(m,0x4c9880);
    if(mode==2 || mode==3) return h2_read32(m,0x4c9884);
    return 0;
}
uint8_t h2_network_game_nonselected_id(h2_memory *m,uint32_t scratch) {
    if(!enabled(m)||h2_network_game_id_matches(m,scratch)) return 0;
    uint32_t current=enabled(m) ? h2_read32(m,0x4c9878) : 0;
    return current!=UINT32_MAX;
}
uint32_t h2_network_game_selected_peer_mask(h2_memory *m,uint32_t scratch) {
    if(!enabled(m)) return 0;
    uint32_t description=h2_network_game_description(m,scratch);
    uint32_t id=h2_network_game_selected_id(m,scratch);
    return description && id!=UINT32_MAX ? h2_read32(m,description+id*0x10c+0xa8) : 0;
}
