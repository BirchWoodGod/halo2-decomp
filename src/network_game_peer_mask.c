#include "halo2/network_game_peer_mask.h"
#include "internal/memory.h"
static uint8_t enabled(h2_memory *m) {return *h2_ptr(m,0x4c99b8,1)&&*h2_ptr(m,0x476fcc,1);}
uint32_t h2_network_game_peer_mask(h2_memory *m,uint32_t members,uint32_t scratch) {
    uint32_t records=0,mask=0;
    if(enabled(m)) {
        uint32_t description=h2_network_game_description(m,scratch);
        if(description) records=description+0x10d4;
    }
    if(enabled(m)) {
        uint32_t description=h2_network_game_description(m,scratch);
        if(description) mask=h2_read32(m,description+0x10d0);
    }
    uint32_t local=h2_network_game_selected_id(m,scratch),result=0;
    if(!records || !mask || local==UINT32_MAX) return 0;
    for(uint32_t i=0;i<16;++i) {
        uint32_t bit=1u<<i;
        if(!(members&bit)||!(mask&bit)) continue;
        uint32_t peer=h2_read32(m,records+12+i*0x13c);
        if(peer!=local && peer!=UINT32_MAX) result|=1u<<(peer&31);
    }
    return result;
}
