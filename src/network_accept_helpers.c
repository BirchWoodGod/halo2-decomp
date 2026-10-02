#include "halo2/network_accept_helpers.h"
#include "internal/memory.h"
static uint32_t word(h2_memory *m,uint32_t a) {const uint8_t *p=h2_ptr(m,a,2);return p[0]|(uint32_t)p[1]<<8;}
uint8_t h2_network_connection_flags_valid(uint32_t f) {
    return !(f&0xffffff00u) && (f&3)!=3 && (f&0xc0)!=0xc0 &&
           (f&12)!=12 && ((f&8) || !(f&0x30)) && ((f&0x10) || !(f&0x20));
}
uint8_t h2_network_connection_copy_address(h2_memory *m,uint32_t connection,uint32_t address) {
    uint32_t state=h2_read32(m,connection+0x54);
    if(!state || state==1) return 0;
    for(uint32_t i=0;i<20;i+=4) h2_write32(m,address+i,h2_read32(m,connection+0x70+i));
    return 1;
}
uint8_t h2_network_address_equal(h2_memory *m,uint32_t first,uint32_t second,uint8_t compare_port) {
    uint32_t a=word(m,first+18),b=word(m,second+18);
    if(!b || b&0x8000 || a!=b) return 0;
    for(uint32_t i=0;i<b;++i) if(*h2_ptr(m,second+i,1)!=*h2_ptr(m,first+i,1)) return 0;
    return !compare_port || word(m,second+16)==word(m,first+16);
}
