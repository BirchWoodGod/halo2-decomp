#include "halo2/network_parameter_variant.h"
#include "internal/memory.h"
#include <stdlib.h>
static uint32_t word(h2_memory *m,uint32_t p) {
    const uint8_t *b=h2_ptr(m,p,2);return b[0]|(uint32_t)b[1]<<8;
}
static uint32_t sword(h2_memory *m,uint32_t p) {
    uint32_t v=word(m,p);return v&0x8000 ? v|UINT32_C(0xffff0000) : v;
}
static uint32_t sbyte(h2_memory *m,uint32_t p) {
    uint32_t v=*h2_ptr(m,p,1);return v&128 ? v|UINT32_C(0xffffff00) : v;
}
static void field(h2_memory *m,const h2_format_operations *ops,uint32_t s,
    uint32_t v,uint32_t bits,uint32_t out,uint32_t args) {
    h2_bitstream_write_checked(m,ops,s,v,bits,out,args);
}
void h2_network_parameter_variant_write(h2_memory *m,const h2_format_operations *ops,
    uint32_t s,uint32_t p,uint32_t out,uint32_t args) {
#define F(v,b) field(m,ops,s,(v),(b),out,args)
#define N(v,b) field(m,ops,s,(v),(b),out+256,args)
#define D(o) h2_read32(m,p+(o))
    F(D(0x44),4);
    if(!D(0x44)) return;
    F(word(m,p),1);
    for(uint32_t i=0;i<32;++i) {
        uint32_t v=word(m,p+4+i*2);h2_bitstream_write_bits(m,s,v,16);if(!v) break;
    }
    F(sbyte(m,p+3)+1,7);F(D(0x48),15);N(D(0x4c),3);
    F(D(0x50),16);F(D(0x54),16);N(D(0x58),2);
    N(D(0x74),5);N(D(0x78),5);
    F(D(0x7c),16);F(D(0x80),16);F(D(0x84),16);
    N(D(0x88),2);N(D(0xa4),2);N(D(0xa8),2);
    F(D(0xac),16);N(D(0xb4),4);
    static const uint8_t widths[]={2,3,3,3,3,3,3,3,5,2,5,5};
    for(uint32_t i=0;i<12;++i) N(sbyte(m,p+0xcc+i),widths[i]);
    uint32_t tag=D(0x44);
    switch(tag) {
    case 9:
        F(sword(m,p+0x108),16);F(sword(m,p+0x10a),16);
        /* fall through */
    case 1:
        F(D(0xf0),8);F(D(0xf4),16);N(D(0xf8),2);
        N(D(0xfc),1);N(D(0x100),2);N(D(0x104),2);break;
    case 2:F(D(0xf0),3);break;
    case 3:
        F(D(0xf0),3);N(sword(m,p+0xf4),2);N(sword(m,p+0xf6),1);
        N(sword(m,p+0xf8),2);N(sword(m,p+0xfa),2);break;
    case 4:F(D(0xf0),5);F(sword(m,p+0xf4),16);break;
    case 7:F(D(0xf0),7);N(sword(m,p+0xf4),2);break;
    case 8:
        N(sword(m,p+0xf0),4);F(sword(m,p+0xf2),16);
        F(sword(m,p+0xf4),16);break;
    default:abort();
    }
#undef D
#undef N
#undef F
}
