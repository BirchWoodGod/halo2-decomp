#include "halo2/network_parameters_encode.h"
#include "halo2/bitstream_checked.h"
#include "halo2/network_parameter_lists.h"
#include "halo2/network_parameter_variant.h"
#include "halo2/network_parameter_record.h"
#include "halo2/network_parameter_block.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {
    return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;
}
static uint32_t word(h2_memory *m,uint32_t p) {
    const uint8_t *b=h2_ptr(m,p,2);return b[0]|(uint32_t)b[1]<<8;
}
static uint32_t sword(h2_memory *m,uint32_t p) {
    uint32_t v=word(m,p);return v&0x8000 ? v|UINT32_C(0xffff0000) : v;
}
static void boolean(h2_memory *m,uint32_t s,uint8_t value) {
    uint32_t pos=h2_read32(m,s+16);
    if(sv((h2_read32(m,s+4)<<3)-pos)>=1 && value)
        *h2_ptr(m,h2_read32(m,s)+(uint32_t)(sv(pos)/8),1)|=
            (uint8_t)(UINT32_C(1)<<((uint32_t)(sv(pos)%8)&31));
    h2_write32(m,s+16,h2_read32(m,s+16)+1);
}
/* Reload the flag after the write, matching the original even for guest aliases. */
static uint8_t flag(h2_memory *m,uint32_t s,uint32_t p) {
    boolean(m,s,*h2_ptr(m,p,1));return *h2_ptr(m,p,1)!=0;
}
void h2_network_parameters_encode(h2_memory *m,const h2_format_operations *ops,
    uint32_t s,uint32_t p,uint32_t out,uint32_t args) {
#define D(o) h2_read32(m,p+(o))
#define B(o) flag(m,s,p+(o))
#define W(v,n) h2_bitstream_write_bits(m,s,(v),(n))
#define F(v,n) h2_bitstream_write_checked(m,ops,s,(v),(n),out,args)
#define G(v,n) h2_bitstream_write_checked(m,ops,s,(v),(n),out+256,args)
#define RAW(o,n) h2_bitstream_write_buffer(m,s,p+(o),(n))
    RAW(0,64);W(D(8),32);
    if(D(12)==UINT32_MAX) boolean(m,s,1);
    else {h2_write32(m,s+16,h2_read32(m,s+16)+1);W(D(12),32);}
    if(B(0x10)) {B(0x11);W(D(0x18),32);F(D(0x14),5);}
    if(B(0x1c)) F(D(0x20),4);
    if(B(0x24)) F(D(0x28),2);
    if(B(0x38) && B(0x39)) RAW(0x3a,64);
    if(B(0x2c)) {F(D(0x30)-1,4);F(D(0x34)-1,4);}
    if(B(0x42)) F(D(0x44),2);
    if(B(0x48)) B(0x49);
    if(B(0x4a)) F(D(0x4c)+1,5);
    if(B(0x50)) B(0x51);
    if(B(0x52)) {
        F(D(0x54),3);uint32_t tag=D(0x54);
        if(tag==1) {F(D(0x58),4);F(D(0x5c),4);F(D(0x60),6);F(D(0x64),10);}
        else if(tag==2) F(D(0x68),10);
        else if(tag==3) F(D(0x6c),10);
    }
    if(B(0x70)) F(D(0x74),5);
    if(B(0x88) && B(0x89)) h2_network_parameter_lists_write(m,ops,p+0x8c,s,out+512,args);
    if(B(0x78) && B(0x79)) RAW(0x80,64);
    if(B(0x394)) {
        W(D(0x398),32);W(D(0x39c),32);
        for(uint32_t i=0;i<128;++i) {uint8_t v=*h2_ptr(m,p+0x3a0+i,1);W(v,8);if(!v) break;}
    }
    if(B(0x420)) RAW(0x428,64);
    if(B(0x430)) W(D(0x434),32);
    if(B(0x438)) F(D(0x43c),2);
    if(B(0x440)) h2_network_parameter_variant_write(m,ops,s,p+0x444,out+512,args);
    if(B(0x574)) {
        for(uint32_t i=0;i<32;++i) {uint32_t v=word(m,p+0x576+i*2);W(v,16);if(!v) break;}
    }
    if(B(0x5b6) && B(0x5b7)) {
        F(D(0x5b8),16);
        for(uint32_t i=0;i<16;++i) if(D(0x5b8)&(UINT32_C(1)<<i)) RAW(0x5bc+i*6,48);
        for(uint32_t i=0;i<16;++i) {
            uint32_t q=p+0x625+i*0xe4;
            if(flag(m,s,q-1)) {
                if(!flag(m,s,q)) {
                    h2_bitstream_write_buffer(m,s,q+7,48);
                    F(sword(m,q+1),2);G(h2_read32(m,q+3),2);
                }
                h2_bitstream_write_buffer(m,s,q+13,96);
                h2_network_parameter_record_write(m,ops,s,q+27,out+512,args);
            }
        }
    }
    if(B(0x1464)) B(0x1465);
    if(B(0x1466)) G(sword(m,p+0x1468)+1,3);
    if(B(0x146a)) {
        B(0x146b);G(D(0x146c),12);G(D(0x1470),2);
        uint32_t tag=D(0x1470);
        if(tag==1 || tag==2) G(D(0x1474),12);
        if(D(0x1470)==1) RAW(0x1478,96);
    }
    if(B(0x1484) && B(0x1485)) h2_network_parameter_block_write(m,ops,s,p+0x1488,out+512,args);
    if(B(0x14cc)) G(D(0x14d0)+1,5);
#undef RAW
#undef G
#undef F
#undef W
#undef B
#undef D
}
