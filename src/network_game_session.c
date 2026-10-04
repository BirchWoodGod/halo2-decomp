#include "halo2/network_game_session.h"
#include "internal/memory.h"
static uint8_t get(h2_memory *m,uint32_t slot,uint32_t output) {
    if(!*h2_ptr(m,0x527330,1)) return 0;
    uint32_t session=h2_read32(m,slot);
    if(!h2_read32(m,session+0x741c)) return 0;
    if(output) h2_write32(m,output,session);
    return 1;
}
uint8_t h2_network_game_session_a(h2_memory *m,uint32_t output) {return get(m,0x527364,output);}
uint8_t h2_network_game_session_b(h2_memory *m,uint32_t output) {return get(m,0x52736c,output);}
uint8_t h2_network_game_session_selected(h2_memory *m,uint32_t output) {
    if(!*h2_ptr(m,0x4c99b8,1)||!*h2_ptr(m,0x476fcc,1)||!h2_read32(m,0x4c9888)) return 0;
    uint32_t selector=h2_read32(m,0x4c988c);
    if(selector==1) return h2_network_game_session_a(m,output);
    if(selector==2) return h2_network_game_session_b(m,output);
    return 0;
}
