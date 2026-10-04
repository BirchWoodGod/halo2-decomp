#include "halo2/network_membership_encode.h"
#include "halo2/bitstream_checked.h"
#include "halo2/network_parameter_record.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t word(h2_memory *m,uint32_t p) {const uint8_t *v=h2_ptr(m,p,2);return v[0]|(uint32_t)v[1]<<8;}
static uint32_t sw(h2_memory *m,uint32_t p) {uint32_t v=word(m,p);return v&0x8000 ? v|UINT32_C(0xffff0000) : v;}
static void boolean(h2_memory *m,uint32_t s,uint8_t v) {
    uint32_t pos=h2_read32(m,s+16);
    if(sv((h2_read32(m,s+4)<<3)-pos)>=1 && v) *h2_ptr(m,h2_read32(m,s)+(uint32_t)(sv(pos)/8),1)|=(uint8_t)(UINT32_C(1)<<((uint32_t)(sv(pos)%8)&31));
    h2_write32(m,s+16,h2_read32(m,s+16)+1);
}
static uint8_t flag(h2_memory *m,uint32_t s,uint32_t p) {boolean(m,s,*h2_ptr(m,p,1));return *h2_ptr(m,p,1)!=0;}
static void name(h2_memory *m,uint32_t s,uint32_t p,uint32_t n) {
    for(uint32_t i=0;i<n;++i) {uint32_t v=word(m,p+i*2);h2_bitstream_write_bits(m,s,v,16);if(!v) break;}
}
void h2_network_membership_encode(h2_memory *m,const h2_format_operations *ops,uint32_t s,uint32_t p,uint32_t out,uint32_t args) {
#define F(v,n,k) h2_bitstream_write_checked(m,ops,s,(v),(n),out+(k)*256,args)
#define D(a) h2_read32(m,(a))
#define RAW(a,n) h2_bitstream_write_buffer(m,s,(a),(n))
#define B(a) flag(m,s,(a))
    RAW(p,64);h2_bitstream_write_bits(m,s,D(p+8),32);
    if(D(p+12)==UINT32_MAX) boolean(m,s,1);
    else {h2_write32(m,s+16,h2_read32(m,s+16)+1);h2_bitstream_write_bits(m,s,D(p+12),32);}
    F(sw(m,p+16),5,1);F(sw(m,p+18),5,1);
    for(uint32_t i=0;sv(i)<sv(sw(m,p+16));++i) {
        uint32_t q=p+0x14+i*0x104;
        if(word(m,q)==65535) boolean(m,s,0);else {boolean(m,s,1);F(sw(m,q),4,1);}
        if(word(m,q+2)==65535) boolean(m,s,0);else {boolean(m,s,1);F(sw(m,q+2),4,9);}
        RAW(q+4,288);
        if(B(q+0x28)) {
            B(q+0x29);
            if(B(q+0x2c)) {name(m,s,q+0x2e,16);name(m,s,q+0x4e,32);}
            if(B(q+0x8e)) {F(D(q+0x90),3,10);F(D(q+0x94),7,6);}
            if(B(q+0x98)) {
                RAW(q+0x9c,32);RAW(q+0xa0,32);F(D(q+0xa4),2,7);F(D(q+0xa8),16,8);
                F(D(q+0xac),11,4);F(D(q+0xb0),11,2);F(D(q+0xb4),11,3);
            }
            if(B(q+0xb8)) for(uint32_t j=0;j<16;++j) F(D(q+0xbc+j*4),2,5);
            if(B(q+0xfc)) F(D(q+0x100),4,0);
        }
    }
    for(uint32_t i=0;sv(i)<sv(sw(m,p+18));++i) {
        uint32_t q=p+0x2094+i*0x140;
        F(sw(m,q),4,0);F(sw(m,q+2),2,5);
        if(word(m,q+2)==1) {RAW(q+4,96);F(sw(m,q+16),4,3);F(sw(m,q+18),2,2);}
        if(B(q+20)) {
            F(D(q+24),2,4);h2_network_parameter_record_write(m,ops,s,q+28,out+0xb00,args);
            h2_network_parameter_record_write(m,ops,s,q+0xac,out+0xb00,args);
            h2_bitstream_write_bits(m,s,D(q+0x13c),32);
        }
    }
    if(B(p+0x4894)) F(D(p+0x4898),4,0);
#undef B
#undef RAW
#undef D
#undef F
}
