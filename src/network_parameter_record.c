#include "halo2/network_parameter_record.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t signed_byte(h2_memory *m,uint32_t p) {uint32_t v=*h2_ptr(m,p,1);return v&128 ? v|UINT32_C(0xffffff00) : v;}
static uint32_t word(h2_memory *m,uint32_t p) {uint8_t *v=h2_ptr(m,p,2);return v[0]|(uint32_t)v[1]<<8;}
static void boolean(h2_memory *m,uint32_t s,uint8_t v) {
    uint32_t p=h2_read32(m,s+16);
    if(sv((h2_read32(m,s+4)<<3)-p)>=1 && v) *h2_ptr(m,h2_read32(m,s)+(uint32_t)(sv(p)/8),1)|=(uint8_t)(UINT32_C(1)<<((uint32_t)(sv(p)%8)&31));
    h2_write32(m,s+16,h2_read32(m,s+16)+1);
}
static void field(h2_memory *m,const h2_format_operations *f,uint32_t s,uint32_t value,uint32_t bits,uint32_t out,uint32_t args) {
    uint32_t limit=UINT32_C(1)<<bits;
    if(value>=limit) {
        *h2_ptr(m,out,1)=0;h2_write32(m,args,value);h2_write32(m,args+4,limit);
        h2_format_string_256(m,f,out,0x453e78,args);
    }
    h2_bitstream_write_bits(m,s,value,bits);
}
static void name(h2_memory *m,uint32_t s,uint32_t p,uint32_t max) {
    for(uint32_t i=0;i<max;++i) {uint32_t v=word(m,p+i*2);h2_bitstream_write_bits(m,s,v,16);if(!v) break;}
}
void h2_network_parameter_record_write(h2_memory *m,const h2_format_operations *f,uint32_t s,uint32_t p,uint32_t out,uint32_t args) {
    name(m,s,p,32);
    /* Preserve nested 0007ee10 diagnostics, which the existing valid-input-only
     * configuration writer does not expose through its current interface. */
    const uint32_t widths[]={5,5,5,5,3,6,6,4};
    for(uint32_t i=0;i<8;++i) {
        uint32_t v=i<5 ? signed_byte(m,p+0x40+i)+1 : *h2_ptr(m,p+0x40+i,1);
        field(m,f,s,v,widths[i],out+256,args);
    }
    uint8_t present=memcmp(h2_ptr(m,p+0x70,12),h2_ptr(m,0x440070,12),12)!=0;
    boolean(m,s,present);
    if(present) {h2_bitstream_write_buffer(m,s,p+0x70,96);name(m,s,p+0x50,16);}
    const uint32_t offsets[]={0x7c,0x7e,0x7f},bits[]={4,7,7};
    for(uint32_t i=0;i<3;++i) {
        boolean(m,s,*h2_ptr(m,p+offsets[i],1)!=255);
        uint32_t v=signed_byte(m,p+offsets[i]);
        if(v!=UINT32_MAX) field(m,f,s,v,bits[i],out,args);
    }
    boolean(m,s,h2_read32(m,p+0x84)!=UINT32_MAX);
    uint32_t v=h2_read32(m,p+0x84);
    if(v!=UINT32_MAX) {
        field(m,f,s,v,4,out,args);
        for(uint32_t off=0x88;off<=0x8a;off+=2) {
            boolean(m,s,word(m,p+off)!=65535);v=word(m,p+off);
            if(v!=65535) {if(v&0x8000) v|=UINT32_C(0xffff0000);field(m,f,s,v,7,out,args);}
        }
        boolean(m,s,h2_read32(m,p+0x8c)!=UINT32_MAX);v=h2_read32(m,p+0x8c);
        if(v!=UINT32_MAX) field(m,f,s,v,30,out,args);
    }
    field(m,f,s,signed_byte(m,p+0x7d),2,out,args);
    boolean(m,s,sv(signed_byte(m,p+0x80))>0);
    field(m,f,s,signed_byte(m,p+0x81),3,out,args);
}
