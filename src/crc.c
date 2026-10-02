#include "halo2/crc.h"
#include "internal/memory.h"

void h2_crc_table_initialize(h2_memory *m, uint32_t table) {
    for (uint32_t i=0;i<256;i++) {
        uint32_t c=i;
        for (unsigned bit=0;bit<8;bit++) c=(c>>1)^((c&1)?UINT32_C(0xedb88320):0);
        h2_write32(m,table+i*4,c);
    }
}
void h2_crc_update_bytes(h2_memory *m,uint32_t accumulator,const uint8_t *data,uint32_t length) {
    if (!*h2_ptr(m,0x55e755,1)) {
        h2_crc_table_initialize(m,0x55e788);
        *h2_ptr(m,0x55e755,1)=1;
    }
    uint32_t c=h2_read32(m,accumulator);
    if (!(length&0x80000000))
        for (uint32_t i=0;i<length;i++) c=(c>>8)^h2_read32(m,0x55e788+((data[i]^c)&255)*4);
    h2_write32(m,accumulator,c);
}
void h2_crc_update(h2_memory *m,uint32_t accumulator,uint32_t data,uint32_t length) {
    const uint8_t *p=(length && !(length&0x80000000))?h2_ptr(m,data,length):NULL;
    h2_crc_update_bytes(m,accumulator,p,length);
}
