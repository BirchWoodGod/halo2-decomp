#include "halo2/network_storage.h"
#include "halo2/crc.h"
#include "internal/memory.h"
#include <string.h>
static int64_t signed32(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t remainder32(uint32_t a,uint32_t b) {
    int64_t dividend=signed32(a),divisor=signed32(b);
    if (!divisor || (dividend==INT32_MIN && divisor==-1)) abort();
    return (uint32_t)(dividend%divisor);
}
static uint32_t bytes_for_bits(uint32_t bits) {return (uint32_t)(signed32(bits+7)/8);}
static void copy_forward(h2_memory *m,uint32_t dst,uint32_t src,uint32_t size) {
    uint32_t words=size>>2;
    for (uint32_t i=0;i<words;++i) h2_write32(m,dst+i*4,h2_read32(m,src+i*4));
    for (uint32_t i=words*4;i<size;++i) *h2_ptr(m,dst+i,1)=*h2_ptr(m,src+i,1);
}
void h2_network_storage_enqueue(h2_memory *m,const h2_network_storage_queue_operations *ops,const h2_message_codec_platform *codec,uint32_t storage,uint32_t type,uint32_t size,uint32_t payload,uint32_t scratch) {
    uint32_t stream=scratch,data=scratch+0x38,crc=scratch+0x34;
    h2_write32(m,stream,data);h2_write32(m,stream+4,0xffff);
    h2_write32(m,stream+8,1);h2_write32(m,stream+12,1);
    memset(h2_ptr(m,data,0xffff),0,0xffff);
    h2_write32(m,stream+16,0);*h2_ptr(m,stream+20,1)=0;
    h2_write32(m,stream+24,0);h2_write32(m,stream+0x2c,0);h2_write32(m,stream+0x30,0);
    uint32_t table=h2_read32(m,storage+12);
    h2_message_header_write(m,stream,type,size);
    codec->encode(codec->context,h2_read32(m,table+type*32+20),stream,size,payload);
    uint32_t remaining=h2_read32(m,stream+16)+32;
    uint32_t crc_bytes=bytes_for_bits(remaining),encoded_bytes=bytes_for_bits(h2_read32(m,stream+16));
    uint32_t remainder=remainder32(encoded_bytes,h2_read32(m,stream+8));
    h2_write32(m,stream+4,encoded_bytes);
    if (remainder) h2_write32(m,stream+4,encoded_bytes+h2_read32(m,stream+8)-remainder);
    h2_write32(m,stream+12,2);h2_write32(m,crc,UINT32_MAX);
    h2_crc_update(m,crc,crc,crc_bytes);
    uint32_t source=crc;
    for (;;) {
        uint32_t function=h2_read32(m,h2_read32(m,storage)+4);
        if (ops->poll(ops->context,function,storage,0)) return;
        if (signed32(h2_read32(m,storage+24)-h2_read32(m,storage+28))>=signed32(h2_read32(m,storage+20))) {
            *h2_ptr(m,storage+5,1)=1;continue;
        }
        int final=signed32(remaining)<=256;
        uint32_t bits=final ? remaining : 256,bytes=final ? bytes_for_bits(remaining) : 32;
        uint32_t wrapper=h2_read32(m,0x4d87f8),object=h2_read32(m,wrapper);
        function=h2_read32(m,h2_read32(m,object)+0x14);
        uint32_t allocation=ops->allocate(ops->context,function,object,bytes,0,0);
        if (!allocation) {
            object=h2_read32(m,wrapper);function=h2_read32(m,h2_read32(m,object)+0x28);
            ops->collect(ops->context,function,object,0);
            object=h2_read32(m,wrapper);function=h2_read32(m,h2_read32(m,object)+0x14);
            allocation=ops->allocate(ops->context,function,object,bytes,0,0);
            if (!allocation) {*h2_ptr(m,storage+5,1)=1;continue;}
        }
        h2_write32(m,wrapper+4,h2_read32(m,wrapper+4)+1);
        uint32_t sequence=h2_read32(m,storage+24)+1,previous=h2_read32(m,storage+24);
        if (signed32(sequence)>signed32(previous)) {
            h2_write32(m,storage+40,h2_read32(m,storage+40)+sequence-previous);
            h2_write32(m,storage+24,sequence);
        }
        uint32_t first=h2_read32(m,storage+28),index=UINT32_MAX;
        if (signed32(sequence)>signed32(first) && signed32(sequence)<=signed32(h2_read32(m,storage+24))) {
            uint32_t origin=h2_read32(m,storage+40) ? h2_read32(m,storage+36) : UINT32_MAX;
            index=remainder32(sequence-first-1+origin,h2_read32(m,storage+20));
        }
        uint32_t entry=index==UINT32_MAX ? 0 : storage+44+index*12;
        copy_forward(m,allocation,source,bytes);
        h2_write32(m,entry,0);h2_write32(m,entry+4,0);h2_write32(m,entry+8,0);
        *h2_ptr(m,entry,1)=4;*h2_ptr(m,entry+1,1)=(uint8_t)bytes;
        h2_write32(m,entry+8,UINT32_MAX);remaining-=256;
        *h2_ptr(m,entry,1)=(uint8_t)(final ? 12 : 4);
        *h2_ptr(m,entry+2,1)=(uint8_t)bits;*h2_ptr(m,entry+3,1)=(uint8_t)(bits>>8);
        h2_write32(m,entry+4,allocation);
        h2_write32(m,storage+0x2848,h2_read32(m,storage+0x2848)+bytes);
        source+=32;
        if (final) return;
    }
}
