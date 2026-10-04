#include "halo2/network_session_migration_start.h"
#include "halo2/network_session_migration_payload.h"
#include "internal/memory.h"
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_session_begin_migration(h2_memory *m,const h2_network_state_operations *clock,uint32_t session,uint32_t scratch) {
    for(uint32_t i=0;i<0x118;i+=4) h2_write32(m,scratch+i,0);
    h2_write32(m,scratch,ticks(m,clock));
    uint32_t local=h2_network_session_build_migration_payload(m,session,scratch+16);
    h2_write32(m,scratch+12,local);
    uint32_t now=ticks(m,clock);
    local=h2_read32(m,session+0x72d8);
    h2_write32(m,scratch+8,now);
    uint32_t local_mask=UINT32_C(1)<<(local&31);
    uint32_t host_mask=UINT32_C(1)<<(h2_read32(m,session+0x40)&31);
    h2_write32(m,scratch+0xd0,local_mask);
    h2_write32(m,session+0x7650,h2_read32(m,session+0x7650)+1);
    for(uint32_t i=0;i<52;i+=4) h2_write32(m,session+0x761c+i,0);
    h2_write32(m,session+0x7654,UINT32_MAX);h2_write32(m,session+0x7658,UINT32_MAX);
    h2_write32(m,scratch+0xd4,host_mask);
    for(uint32_t i=0;i<0x1f8;i+=4) h2_write32(m,session+0x7420+i,0);
    for(uint32_t i=0;i<0x118;i+=4) h2_write32(m,session+0x7420+i,h2_read32(m,scratch+i));
    h2_write32(m,session+0x741c,9);
}
