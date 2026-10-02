#include "halo2/session_description.h"
#include "halo2/bitstream.h"
#include "halo2/network_messages.h"
#include "halo2/text_codec.h"
#include "internal/memory.h"
static uint32_t word(h2_memory *m, uint32_t p) {
    const uint8_t *b=h2_ptr(m,p,2);return b[0]|(uint32_t)b[1]<<8;
}
static void put_word(h2_memory *m, uint32_t p, uint32_t value) {
    uint8_t *b=h2_ptr(m,p,2);b[0]=(uint8_t)value;b[1]=(uint8_t)(value>>8);
}
static int32_t signed_word(uint32_t x) {return x&0x8000 ? (int32_t)x-65536 : (int32_t)x;}
uint8_t h2_session_description_valid(h2_memory *m, uint32_t d) {
    if (!d || word(m,d+2)>=2 || h2_read32(m,d+4)>=5) return 0;
    uint32_t first=h2_read32(m,d+8),second=h2_read32(m,d+12);
    if (first!=0xffffffff && (first==0 || first>65534)) return 0;
    /* Original compares the first field again for the second upper bound. */
    if (second!=0xffffffff && (second==0 || (second&0x80000000) ||
        (!(first&0x80000000) && first>65534))) return 0;
    for (uint32_t p=16;p<=20;p+=2) if (word(m,d+p)>=3) return 0;
    for (uint32_t p=0x94;p<=0x9a;p+=2) if (word(m,d+p)>16) return 0;
    if (word(m,d+0x9c)>=5 || word(m,d+0x9e)>=10) return 0;
    if (h2_read32(m,d+0xb4)>=3 || (h2_read32(m,d+0xb8)&0x80000000) ||
        word(m,d+0xbc)>16 || (h2_read32(m,d+0x6e0)&0xffffff00)) return 0;
    uint32_t last=h2_read32(m,d+0xa8);
    return last==0xffffffff || last<4;
}
uint8_t h2_session_description_read(h2_memory *m, uint32_t s, uint32_t d, uint32_t scratch) {
    put_word(m,d,h2_bitstream_read_bits(m,s,8));
    put_word(m,d+2,h2_bitstream_read_bits(m,s,2));
    h2_write32(m,d+4,h2_bitstream_read_bits(m,s,3));
    h2_write32(m,d+8,h2_bitstream_read_bits(m,s,16)-1);
    h2_write32(m,d+12,h2_bitstream_read_bits(m,s,16)-1);
    for (uint32_t p=16;p<=20;p+=2) put_word(m,d+p,h2_bitstream_read_bits(m,s,2));
    h2_bitstream_read_buffer(m,s,scratch+12,256);
    h2_text_decode_string(m,scratch+12,d+24,32);
    h2_bitstream_read_buffer(m,s,d+0x58,64);
    h2_bitstream_read_buffer(m,s,d+0x60,128);
    h2_bitstream_read_buffer(m,s,d+0x70,288);
    for (uint32_t p=0x94;p<=0x9a;p+=2) put_word(m,d+p,h2_bitstream_read_bits(m,s,5));
    put_word(m,d+0x9c,h2_bitstream_read_bits(m,s,3));
    put_word(m,d+0x9e,h2_bitstream_read_bits(m,s,4));
    h2_write32(m,d+0xa0,h2_bitstream_read_bits(m,s,4));
    h2_write32(m,d+0xa4,h2_bitstream_read_bits(m,s,32));
    h2_write32(m,d+0xa8,h2_bitstream_read_bits(m,s,3)-1);
    h2_write32(m,d+0xac,h2_bitstream_read_bits(m,s,32));
    *h2_ptr(m,d+0xb0,1)=h2_bitstream_read_bool(m,s);
    h2_write32(m,d+0xb4,h2_bitstream_read_bits(m,s,2));
    h2_write32(m,d+0xb8,h2_bitstream_read_bits(m,s,32));
    uint32_t count=h2_bitstream_read_bits(m,s,5);
    put_word(m,d+0xbc,count);
    uint8_t valid=signed_word(count&0xffff)>=0 && signed_word(count&0xffff)<=16;
    uint32_t extra=h2_bitstream_read_bits(m,s,5);
    int32_t actual=signed_word(word(m,d+0xbc));
    valid=valid && (int64_t)extra>=actual && extra<=16;
    /* Loop bound is captured; the output count is reread for each copy. */
    if (valid) for (uint32_t i=0;i<extra;++i) {
        h2_bitstream_read_buffer(m,s,scratch,96);
        h2_bitstream_read_buffer(m,s,scratch+44,256);
        uint32_t scalar=h2_bitstream_read_bits(m,s,32);
        uint32_t index=h2_bitstream_read_bits(m,s,5);
        (void)h2_message_config_fields_read(m,s,scratch+12);
        if ((int64_t)i<signed_word(word(m,d+0xbc))) {
            for (uint32_t j=0;j<12;j+=4) h2_write32(m,d+0xbe + i*12+j,h2_read32(m,scratch+j));
            h2_text_decode_string(m,scratch+44,d+0x17e + i*64,32);
            h2_write32(m,d+0x580+i*4,scalar);
            put_word(m,d+0x5c0+i*2,index-1);
            for (uint32_t j=0;j<16;j+=4) h2_write32(m,d+0x5e0+i*16+j,h2_read32(m,scratch+12+j));
        }
    }
    h2_write32(m,d+0x6e0,h2_bitstream_read_bits(m,s,8));
    uint32_t mask=h2_bitstream_read_bits(m,s,8);
    for (uint32_t i=0;i<8;++i) if (mask&(1u<<i)) {
        uint32_t value=h2_bitstream_read_bits(m,s,32);
        if (h2_read32(m,d+0x6e0)&(1u<<i)) h2_write32(m,d+0x6e4+i*4,value);
    }
    uint8_t present=h2_bitstream_read_bool(m,s);
    *h2_ptr(m,d+0x704,1)=present;
    if (present) h2_bitstream_read_buffer(m,s,d+0x705,96);
    else for (uint32_t i=0;i<12;i+=4) h2_write32(m,d+0x705+i,0);
    return valid && !h2_bitstream_has_error(m,s) && h2_session_description_valid(m,d);
}

static int64_t description_signed(uint32_t x) {
    return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;
}
static void description_flag(h2_memory *m, uint32_t s, uint32_t flag) {
    uint32_t position=h2_read32(m,s+16);
    if (description_signed((h2_read32(m,s+4)<<3)-position)>=1 && *h2_ptr(m,flag,1)) {
        uint32_t byte=(uint32_t)(description_signed(position)/8);
        uint32_t shift=(uint32_t)(description_signed(position)%8)&31;
        *h2_ptr(m,h2_read32(m,s)+byte,1)|=(uint8_t)(1u<<shift);
    }
    h2_write32(m,s+16,h2_read32(m,s+16)+1);
}
void h2_session_description_write(h2_memory *m, uint32_t s, uint32_t d, uint32_t scratch) {
    h2_text_encode_string(m,d+24,scratch+32,32);
    h2_bitstream_write_bits(m,s,(uint32_t)signed_word(word(m,d)),8);
    h2_bitstream_write_bits(m,s,(uint32_t)signed_word(word(m,d+2)),2);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+4),3);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+8)+1,16);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+12)+1,16);
    for (uint32_t p=16;p<=20;p+=2) h2_bitstream_write_bits(m,s,(uint32_t)signed_word(word(m,d+p)),2);
    h2_bitstream_write_buffer(m,s,scratch+32,256);
    h2_bitstream_write_buffer(m,s,d+0x58,64);
    h2_bitstream_write_buffer(m,s,d+0x60,128);
    h2_bitstream_write_buffer(m,s,d+0x70,288);
    for (uint32_t p=0x94;p<=0x9a;p+=2) h2_bitstream_write_bits(m,s,(uint32_t)signed_word(word(m,d+p)),5);
    h2_bitstream_write_bits(m,s,(uint32_t)signed_word(word(m,d+0x9c)),3);
    h2_bitstream_write_bits(m,s,(uint32_t)signed_word(word(m,d+0x9e)),4);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+0xa0),4);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+0xa4),32);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+0xa8)+1,3);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+0xac),32);
    description_flag(m,s,d+0xb0);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+0xb4),2);
    h2_bitstream_write_bits(m,s,h2_read32(m,d+0xb8),32);
    h2_bitstream_write_bits(m,s,(uint32_t)signed_word(word(m,d+0xbc)),5);
    int32_t count=signed_word(word(m,d+0xbc));
    h2_write32(m,scratch+28,(uint32_t)count);
    h2_bitstream_write_bits(m,s,(uint32_t)count,5);
    for (int32_t i=0;i<count;++i) {
        uint32_t scalar=0,index=0xffffffff;
        if (i<signed_word(word(m,d+0xbc))) {
            for (uint32_t j=0;j<12;j+=4) h2_write32(m,scratch+j,h2_read32(m,d+0xbe + (uint32_t)i*12+j));
            uint32_t name=d+0x17e + (uint32_t)i*64;
            for (uint32_t j=0;j<32;j+=4) h2_write32(m,scratch+32+j,h2_read32(m,name+j));
            h2_text_encode_string(m,name,scratch+32,32);
            scalar=h2_read32(m,d+0x580+(uint32_t)i*4);
            index=word(m,d+0x5c0+(uint32_t)i*2);
            for (uint32_t j=0;j<16;j+=4) h2_write32(m,scratch+12+j,h2_read32(m,d+0x5e0+(uint32_t)i*16+j));
        } else {
            for (uint32_t j=0;j<28;j+=4) h2_write32(m,scratch+j,0);
            for (uint32_t j=32;j<64;j+=4) h2_write32(m,scratch+j,0);
        }
        h2_bitstream_write_buffer(m,s,scratch,96);
        h2_bitstream_write_buffer(m,s,scratch+32,256);
        h2_bitstream_write_bits(m,s,scalar,32);
        h2_bitstream_write_bits(m,s,(uint32_t)signed_word(index&0xffff)+1,5);
        h2_message_config_fields_write(m,s,scratch+12);
    }
    h2_bitstream_write_bits(m,s,h2_read32(m,d+0x6e0),8);
    uint32_t mask=h2_read32(m,d+0x6e0);
    h2_bitstream_write_bits(m,s,mask,8);
    for (uint32_t i=0;i<8;++i) {
        uint32_t value=0;
        if (h2_read32(m,d+0x6e0)&(1u<<i)) value=h2_read32(m,d+0x6e4+i*4);
        if (mask&(1u<<i)) h2_bitstream_write_bits(m,s,value,32);
    }
    description_flag(m,s,d+0x704);
    if (*h2_ptr(m,d+0x704,1)) h2_bitstream_write_buffer(m,s,d+0x705,96);
}
void h2_message_broadcast_reply_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch) {
    (void)size;
    h2_bitstream_write_bits(m,stream,word(m,payload),16);
    h2_bitstream_write_buffer(m,stream,payload+4,64);
    h2_session_description_write(m,stream,payload+12,scratch);
}
uint8_t h2_message_broadcast_reply_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch) {
    (void)size;
    put_word(m,payload,h2_bitstream_read_bits(m,stream,16));
    h2_bitstream_read_buffer(m,stream,payload+4,64);
    return h2_session_description_read(m,stream,payload+12,scratch) && !h2_bitstream_has_error(m,stream);
}
