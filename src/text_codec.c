#include "halo2/text_codec.h"
#include "internal/memory.h"
static int64_t text_signed(uint32_t x) {
    return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;
}
static uint32_t text_word(h2_memory *m, uint32_t p) {
    const uint8_t *b=h2_ptr(m,p,2);return b[0]|(uint32_t)b[1]<<8;
}
static void text_put_word(h2_memory *m, uint32_t p, uint32_t v) {
    uint8_t *b=h2_ptr(m,p,2);b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);
}
uint32_t h2_text_encode_character(h2_memory *m, uint32_t output, uint32_t value, uint32_t capacity) {
    uint32_t width,first;
    if (value<=0x7f) {width=1;first=value;}
    else if (value<=0x7ff) {width=2;first=(value|0x3000)>>6;}
    else if (value<=0xffff) {width=3;first=(value|0xe0000)>>12;}
    else if (value<=0x1fffff) {width=4;first=(value|0x3c00000)>>18;}
    else return 0;
    if (text_signed(capacity)>0) *h2_ptr(m,output,1)=(uint8_t)first;
    for (uint32_t i=1;i<width && text_signed(i)<text_signed(capacity);++i)
        *h2_ptr(m,output+i,1)=(uint8_t)(0x80|((value>>((width-i)*6-6))&0x3f));
    return width;
}
void h2_text_encode_string(h2_memory *m, uint32_t source, uint32_t output, uint32_t capacity) {
    uint32_t used=0;
    while (text_word(m,source)) {
        uint32_t remaining=capacity-used;
        uint32_t width=h2_text_encode_character(m,output+used,text_word(m,source),remaining);
        used+=text_signed(width)<=text_signed(remaining) ? width : remaining;
        source+=2;
    }
    if (text_signed(used)<text_signed(capacity)) *h2_ptr(m,output+used,1)=0;
    else if (text_signed(used)>0) *h2_ptr(m,output+used-1,1)=0;
}
void h2_text_decode_string(h2_memory *m, uint32_t source, uint32_t output, uint32_t capacity) {
    uint32_t input=0,used=0;
    while (*h2_ptr(m,source+input,1)) {
        uint32_t lead=*h2_ptr(m,source+input,1),value=lead,width=1;
        uint8_t valid=1;
        if (lead&0x80) {
            if ((lead&0xe0)==0xc0) {value=lead&0x1f;width=2;}
            else if ((lead&0xf0)==0xe0) {value=lead&0xf;width=3;}
            else if ((lead&0xf8)==0xf0) {value=lead&7;width=4;}
            else valid=0;
        }
        for (uint32_t i=1;valid && i<width;++i) {
            uint32_t byte=*h2_ptr(m,source+input+i,1);
            value=(value<<6)|(byte&0x3f);
            if ((byte&0xc0)!=0x80) valid=0;
        }
        input+=valid ? width : 1;
        if (valid && text_signed(used)<text_signed(capacity)) text_put_word(m,output+2*used++,value);
    }
    if (text_signed(used)<text_signed(capacity)) text_put_word(m,output+2*used,0);
    else if (text_signed(used)>0) text_put_word(m,output+2*used-2,0);
}
