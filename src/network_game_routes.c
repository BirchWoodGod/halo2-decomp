#include "halo2/network_game_routes.h"
#include "internal/memory.h"
static void w16(h2_memory *m,uint32_t p,uint32_t v) {uint8_t *b=h2_ptr(m,p,2);b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);}
void h2_network_game_build_routes(h2_memory *m,uint32_t table,uint32_t requested,uint32_t output,uint32_t scratch) {
    w16(m,output+2,0);w16(m,output,0);
    if(!*h2_ptr(m,table,1)||!requested) return;
    uint32_t limit=h2_network_game_route_limit(m);
    if(!limit||(limit&0x80000000u)) return;
    h2_write32(m,scratch,limit);
    uint8_t reserve=h2_network_game_nonselected_id(m,scratch+16);
    uint8_t active=*h2_ptr(m,0x4c99b8,1);
    uint32_t local=active&&*h2_ptr(m,0x476fcc,1) ? h2_read32(m,0x4c9878) : 0;
    uint32_t mode=active ? h2_read32(m,0x4c987c) : 0;
    uint32_t available=h2_network_game_selected_peer_mask(m,scratch+16),local_bit=1u<<(local&31);
    uint32_t selected=0,external=0;
    h2_write32(m,scratch+4,0);*h2_ptr(m,scratch+12,1)=0;h2_write32(m,scratch+8,requested);
    if(!(available&local_bit)) reserve=0;
    if(reserve && (mode==1 || mode==2)) *h2_ptr(m,scratch+12,1)=1;
    else {
        if(!reserve && mode==2) h2_write32(m,scratch,1);
        uint32_t kind=h2_network_game_session_kind(m);
        external=(~available)&requested;
        h2_write32(m,scratch+8,requested&available);
        if(external&0xffff) *h2_ptr(m,scratch+12,1)=1;
        if(kind==2) {
            uint32_t overlap=h2_network_game_session_overlap(m,scratch+16);
            h2_network_game_select_routes(m,scratch,scratch+8,overlap,scratch+4,reserve,local,scratch+12);
        }
        if(h2_read32(m,scratch)!=1 || !reserve || !*h2_ptr(m,scratch+12,1))
            h2_network_game_select_routes(m,scratch,scratch+8,UINT32_MAX,scratch+4,reserve,local,scratch+12);
        selected=h2_read32(m,scratch+4);
    }
    if(!reserve) external=0;
    else if(*h2_ptr(m,scratch+12,1)) {selected|=local_bit;external|=h2_read32(m,scratch+8);}
    else if(h2_read32(m,scratch+8)&local_bit) {selected|=local_bit;external|=local_bit;}
    w16(m,output,selected);w16(m,output+2,external);
}
