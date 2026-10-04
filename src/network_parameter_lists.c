#include "halo2/network_parameter_lists.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static void warn(h2_memory *m,const h2_format_operations *f,uint32_t out,uint32_t args,uint32_t value,uint32_t limit) {
    *h2_ptr(m,out,1)=0;h2_write32(m,args,value);h2_write32(m,args+4,limit);
    h2_format_string_256(m,f,out,0x453e78,args);
}
/* The original inline boolean write only sets a true bit; false preserves it.
 * It increments position even when there is insufficient capacity. */
static void boolean(h2_memory *m,uint32_t stream,uint8_t value) {
    uint32_t position=h2_read32(m,stream+16);
    if(sv((h2_read32(m,stream+4)<<3)-position)>=1 && value) {
        uint32_t byte=(uint32_t)(sv(position)/8),shift=(uint32_t)(sv(position)%8)&31;
        *h2_ptr(m,h2_read32(m,stream)+byte,1)|=(uint8_t)(UINT32_C(1)<<shift);
    }
    h2_write32(m,stream+16,h2_read32(m,stream+16)+1);
}
void h2_network_parameter_lists_write(h2_memory *m,const h2_format_operations *f,uint32_t block,uint32_t stream,uint32_t scratch,uint32_t args) {
    uint32_t count=h2_read32(m,block);
    if(count>=32) warn(m,f,scratch,args,count,32);
    h2_bitstream_write_bits(m,stream,count,5);
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,block));++i) {
        h2_bitstream_write_buffer(m,stream,block+4+i*8,64);
        uint32_t identity=block+0x84+i*12;
        uint8_t present=memcmp(h2_ptr(m,identity,12),h2_ptr(m,0x440070,12),12)!=0;
        boolean(m,stream,present);
        if(present) h2_bitstream_write_buffer(m,stream,identity,96);
        h2_bitstream_write_buffer(m,stream,block+0x144+i*4,32);
    }
    count=h2_read32(m,block+0x184);
    if(count>=32) warn(m,f,scratch,args,count,32);
    h2_bitstream_write_bits(m,stream,count,5);
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,block+0x184));++i) {
        h2_bitstream_write_buffer(m,stream,block+0x188+i*12,96);
        uint32_t entry=block+0x248+i*4,value=h2_read32(m,entry+0x80);
        if(value>=32) warn(m,f,scratch,args,value,32);
        h2_bitstream_write_bits(m,stream,value,5);
        boolean(m,stream,h2_read32(m,entry)!=UINT32_MAX);
        value=h2_read32(m,entry);
        if(value!=UINT32_MAX) {
            if(value>=128) warn(m,f,scratch+256,args,value,128);
            h2_bitstream_write_bits(m,stream,value,7);
        }
        boolean(m,stream,h2_read32(m,entry+0x40)!=UINT32_MAX);
        value=h2_read32(m,entry+0x40);
        if(value!=UINT32_MAX) {
            if(value>=UINT32_C(0x40000000)) warn(m,f,scratch+512,args,value,UINT32_C(0x40000000));
            h2_bitstream_write_bits(m,stream,value,30);
        }
    }
}
