#include "halo2/network_session_peer_lookup.h"
#include "internal/memory.h"
#include <string.h>
uint32_t h2_network_session_find_peer_identity(h2_memory *m,uint32_t table,uint32_t identity) {
    uint32_t count=h2_read32(m,table+0x54),result=UINT32_MAX;
    uint8_t key[6];memcpy(key,h2_ptr(m,identity+10,6),6);
    if(count&UINT32_C(0x80000000)) return result;
    for(uint32_t i=0;i<count;++i)
        if(!memcmp(key,h2_ptr(m,table+0x58+i*6,6),6)) result=i;
    return result;
}
