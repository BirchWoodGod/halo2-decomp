#include "halo2/network_registration.h"
#include "internal/memory.h"
void h2_network_registration_release(h2_memory *m,const h2_network_registration_platform *ops) {
    uint32_t index=h2_read32(m,0x5107dc);
    if (index==UINT32_MAX) return;
    uint32_t entry=UINT32_C(0x510588)+index*UINT32_C(0x4a);
    uint32_t address=h2_read32(m,0x5107e0);
    if (address) {
        (void)ops->release_address(ops->context,address);
        h2_write32(m,0x5107e0,0);
    }
    (void)ops->release_key(ops->context,entry+0x30);
    h2_write32(m,0x5107e4,h2_read32(m,0x5107e4)-1);
    h2_write32(m,0x5107dc,UINT32_MAX);
    h2_write32(m,0x5107e0,0);
}
