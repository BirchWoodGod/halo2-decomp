#include "halo2/network_session_migration_payload.h"
#include "internal/memory.h"
#include <string.h>
uint32_t h2_network_session_build_migration_payload(h2_memory *m,uint32_t session,uint32_t out) {
    for(uint32_t i=0;i<0xc0;i+=4) h2_write32(m,out+i,0);
    uint32_t src=session+h2_read32(m,session+0x40)*0x10c+0x58;
    for(uint32_t i=0;i<36;i+=4) h2_write32(m,out+i,h2_read32(m,src+i));
    src=session+h2_read32(m,session+0x72d8)*0x10c+0x58;
    for(uint32_t i=0;i<36;i+=4) h2_write32(m,out+36+i,h2_read32(m,src+i));
    h2_write32(m,out+0x48,h2_read32(m,session+0x4c));
    h2_write32(m,out+0x4c,h2_read32(m,session+0x72d8));
    src=session+h2_read32(m,session+0x72d8)*0x10c;
    h2_write32(m,out+0x50,h2_read32(m,src+0xec));
    src=session+h2_read32(m,session+0x72d8)*0x10c+0x62;
    h2_write32(m,out+0x58,h2_read32(m,src));
    uint8_t tail[2];memcpy(tail,h2_ptr(m,src+4,2),2);memcpy(h2_ptr(m,out+0x5c,2),tail,2);
    h2_write32(m,out+0x54,1);h2_write32(m,out+0xb8,1);h2_write32(m,out+0xbc,1);
    return h2_read32(m,session+0x72d8);
}
