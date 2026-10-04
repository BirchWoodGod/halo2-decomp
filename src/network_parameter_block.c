#include "halo2/network_parameter_block.h"
#include "internal/memory.h"
static void diagnostic(h2_memory *m,const h2_format_operations *f,uint32_t out,uint32_t args,uint32_t value,uint32_t limit) {
    *h2_ptr(m,out,1)=0;h2_write32(m,args,value);h2_write32(m,args+4,limit);
    h2_format_string_256(m,f,out,0x453e78,args);
}
void h2_network_parameter_block_write(h2_memory *m,const h2_format_operations *f,uint32_t stream,uint32_t block,uint32_t out,uint32_t args) {
    uint32_t kind=h2_read32(m,block);
    if(kind>=2) diagnostic(m,f,out,args,kind,2);
    h2_bitstream_write_bits(m,stream,kind,1);
    h2_bitstream_write_buffer(m,stream,block+4,64);
    h2_bitstream_write_buffer(m,stream,block+12,128);
    h2_bitstream_write_buffer(m,stream,block+28,288);
    uint32_t mode=h2_read32(m,block+64);
    if(mode>=4) diagnostic(m,f,out,args,mode,4);
    h2_bitstream_write_bits(m,stream,mode,2);
}
