#include "halo2/network_slot_alloc.h"
#include "internal/memory.h"
uint32_t h2_network_stream_allocate(h2_memory *m,const h2_network_state_operations *clock,uint32_t owner) {
    if (!*h2_ptr(m,0x4d8ba0,1)) return UINT32_MAX;
    uint32_t count=h2_read32(m,0x4d87d0);
    if (!count || (count&0x80000000u)) return UINT32_MAX;
    uint32_t base=h2_read32(m,0x4d87d8);
    for (uint32_t i=0;i<count;++i) {
        uint32_t slot=base+i*0x97c;
        if (*h2_ptr(m,slot+4,1)) continue;
        h2_network_stream_reset(m,clock,slot);
        h2_write32(m,slot+8,owner);*h2_ptr(m,slot+4,1)=1;
        return i;
    }
    return UINT32_MAX;
}
uint32_t h2_network_storage_allocate(h2_memory *m,const h2_network_storage_operations *ops,uint32_t owner,uint32_t scratch) {
    if (!*h2_ptr(m,0x4d8ba0,1)) return UINT32_MAX;
    uint32_t count=h2_read32(m,0x4d87d0);
    if (!count || (count&0x80000000u)) return UINT32_MAX;
    uint32_t base=h2_read32(m,0x4d87dc);
    for (uint32_t i=0;i<count;++i) {
        uint32_t slot=base+i*0x2850;
        if (*h2_ptr(m,slot+4,1)) continue;
        h2_network_storage_clear(m,ops,slot,scratch);
        h2_write32(m,slot+8,owner);*h2_ptr(m,slot+4,1)=1;
        h2_write32(m,slot+12,0x528588);
        return i;
    }
    return UINT32_MAX;
}
