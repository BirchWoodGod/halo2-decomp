#include "halo2/network_session_snapshot_reset.h"
#include "internal/memory.h"
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
static void zero(h2_memory *m,uint32_t p,uint32_t n) {
    for(uint32_t i=0;i<n;++i) h2_write32(m,p+i*4,0);
}
void h2_network_session_reset_snapshots(h2_memory *m,uint32_t session,uint8_t refresh) {
    zero(m,session+0x24e0,0x925);h2_write32(m,session+0x24e0,UINT32_MAX);
    zero(m,session+0x5e28,0x52c);h2_write32(m,session+0x5e28,UINT32_MAX);
    zero(m,session+0x7668,0x90);
    uint32_t count=h2_read32(m,session+0x54);
    *h2_ptr(m,session+0x765c,1)=0;h2_write32(m,session+0x44,UINT32_MAX);
    for(uint32_t i=0;sv(i)<sv(count);++i) {
        uint32_t peer=session+0x72e4+i*20;
        *h2_ptr(m,peer-6,1)=0;h2_write32(m,peer,UINT32_MAX);
        h2_write32(m,peer+4,UINT32_MAX);*h2_ptr(m,peer-5,1)=0;
        count=h2_read32(m,session+0x54);
    }
    if(refresh) {
        h2_write32(m,session+0x4990,16);h2_write32(m,session+0x4994,16);
        h2_write32(m,session+0x4978,h2_read32(m,session+0x4978)+1);
    }
}
