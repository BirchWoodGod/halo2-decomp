#include "halo2/network_game_overlap.h"
#include "halo2/network_session.h"
#include "internal/memory.h"
uint32_t h2_network_game_session_kind(h2_memory *m) {
    return *h2_ptr(m,0x4c99b8,1)&&*h2_ptr(m,0x476fcc,1) ? h2_read32(m,0x4c988c) : 0;
}
uint32_t h2_network_game_session_overlap(h2_memory *m,uint32_t scratch) {
    if(!*h2_ptr(m,0x4c99b8,1)||!*h2_ptr(m,0x476fcc,1)||h2_read32(m,0x4c988c)!=2) return 0;
    h2_write32(m,scratch+4,0);h2_write32(m,scratch,0);
    if(!h2_network_game_session_b(m,scratch)||!h2_network_game_session_a(m,scratch+4)) return 0;
    uint32_t b=h2_read32(m,scratch),description=0;
    if(h2_read32(m,b+0x741c)&&h2_read32(m,b+0x4c)!=UINT32_MAX) description=b+0x4c;
    uint32_t count=h2_read32(m,description+8),result=0;
    if(count&0x80000000u) return 0;
    uint32_t a=h2_read32(m,scratch+4);
    for(uint32_t i=0;i<count;++i)
        if(h2_network_session_find_peer(m,a,description+12+i*0x10c)!=UINT32_MAX) result|=1u<<(i&31);
    return result;
}
