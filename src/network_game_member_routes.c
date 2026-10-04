#include "halo2/network_game_member_routes.h"
#include "internal/memory.h"
void h2_network_game_member_routes(h2_memory *m,uint32_t members,uint32_t table,uint32_t output,uint32_t scratch) {
    uint8_t *p=h2_ptr(m,output,4);p[2]=0;p[3]=0;p[0]=0;p[1]=0;
    if(!*h2_ptr(m,table,1)||!members) return;
    uint32_t peers=h2_network_game_peer_mask(m,members,scratch);
    if(peers) h2_network_game_build_routes(m,table,peers,output,scratch);
}
