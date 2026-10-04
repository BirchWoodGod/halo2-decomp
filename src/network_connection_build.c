#include "halo2/network_connection_build.h"
#include "halo2/network_connection_iteration.h"
#include "halo2/bitstream.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static void iterator(h2_memory *m,uint32_t p,uint32_t flags) {
    h2_write32(m,p,flags);h2_write32(m,p+4,UINT32_MAX);h2_write32(m,p+8,UINT32_MAX);
    h2_write32(m,p+12,0);h2_write32(m,p+16,0);
}
static uint32_t invoke(h2_memory *m,const h2_connection_build_callbacks *c,
    uint32_t object,uint32_t slot,uint32_t count,uint32_t a,uint32_t b,uint32_t d,uint32_t e) {
    uint32_t function=h2_read32(m,h2_read32(m,object)+slot);
    return c->invoke(c->context,function,object,count,a,b,d,e);
}
void h2_network_connection_build_packet(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_stream_reserve_callbacks *reserve_callbacks,
    const h2_connection_build_callbacks *c,uint8_t reserve,uint32_t connection,uint32_t stream,
    uint8_t fill,uint32_t secondary_size,uint32_t secondary,uint32_t accounted_output,
    uint32_t primary_output,uint32_t secondary_output,uint32_t scratch,uint8_t workspace[28]) {
    uint32_t it=scratch+0x10;
    h2_write32(m,scratch+12,UINT32_MAX);*h2_ptr(m,scratch+0x2c,1)=0;
    h2_write32(m,scratch+8,0);h2_write32(m,scratch+0x24,0);h2_write32(m,scratch+0x28,0);
    if(reserve) {
        uint32_t selected=h2_read32(m,0x4d87d8)+h2_read32(m,connection+16)*0x97c;
        uint32_t now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
        uint32_t sequence=h2_network_stream_reserve(m,clock,reserve_callbacks,selected,now,scratch+0x1f74);
        h2_write32(m,scratch+12,sequence);
        if(sequence==UINT32_MAX) goto finish;
    }
    uint32_t bytes=h2_read32(m,stream+4),buffer=h2_read32(m,stream);
    h2_write32(m,stream+12,1);h2_write32(m,stream+8,8);
    memset(h2_ptr(m,buffer,bytes),0,bytes);
    uint32_t mode=h2_read32(m,stream+12);
    h2_write32(m,scratch,0);h2_write32(m,stream+16,0);h2_write32(m,stream+24,0);
    *h2_ptr(m,stream+20,1)=0;
    if(mode==1) {h2_write32(m,stream+44,0);h2_write32(m,stream+48,0);}
    else if(mode==3 || mode==4) {
        if(h2_bitstream_read_bits(m,stream,32)==0x64656267) *h2_ptr(m,stream+20,1)=1;
        else {h2_write32(m,stream+16,0);*h2_ptr(m,stream+20,1)=0;}
    }
    uint32_t budget=h2_read32(m,stream+4)*8-h2_read32(m,stream+16);
    uint32_t provider=h2_read32(m,connection+0x3c);
    uint32_t flags=!(provider && *h2_ptr(m,provider+0x31,1));
    h2_write32(m,scratch+4,flags);*h2_ptr(m,connection+0x1c,1)=(uint8_t)!flags;
    memset(h2_ptr(m,scratch+0x30,28),0,28);iterator(m,it,flags);
    while(h2_network_connection_next_component(m,connection,it)) {
        uint32_t used=h2_read32(m,scratch);
        uint32_t needed=invoke(m,c,h2_read32(m,it+16),12,2,budget,budget-used,0,0);
        uint32_t index=h2_read32(m,it+8);
        h2_write32(m,scratch,used+needed);h2_write32(m,scratch+0x30+index*4,needed);
    }
    uint32_t remaining=h2_read32(m,scratch)+1;h2_write32(m,scratch,remaining);
    if(sv(remaining)>sv(budget)) goto finish;
    iterator(m,it,h2_read32(m,scratch+4));
    while(h2_network_connection_next_component(m,connection,it)) {
        uint32_t needed=h2_read32(m,scratch+0x30+h2_read32(m,it+8)*4);
        remaining=h2_read32(m,scratch)-needed;h2_write32(m,scratch,remaining);
        uint32_t result=invoke(m,c,h2_read32(m,it+16),16,4,h2_read32(m,scratch+12),stream,needed,remaining);
        if((uint8_t)result) *h2_ptr(m,scratch+0x2c,1)=1;
        if(sv(h2_read32(m,stream+4)*8-h2_read32(m,stream+16))<sv(remaining)) goto finish;
    }
    remaining=h2_read32(m,stream+4)*8-h2_read32(m,stream+16);
    if(fill && sv(remaining)>15) {
        uint32_t bits=remaining-15;
        uint32_t zero_bytes=(uint32_t)(sv(bits+7)/8);h2_write32(m,scratch+4,zero_bytes);
        uint32_t position=h2_read32(m,stream+16);
        uint32_t address=h2_read32(m,stream)+(uint32_t)(sv(position)/8);
        uint32_t shift=(uint32_t)(sv(position)%8)&31;
        *h2_ptr(m,address,1)|=(uint8_t)(UINT32_C(1)<<shift);
        h2_write32(m,stream+16,h2_read32(m,stream+16)+1);
        if(bits>=0x4000) {
            *h2_ptr(m,scratch+0x4c,1)=0;
            h2_write32(m,scratch+0x1f7c,bits);h2_write32(m,scratch+0x1f80,0x4000);
            (void)h2_format_string_256(m,&c->formatting,scratch+0x4c,0x453e78,scratch+0x1f7c);
        }
        h2_bitstream_write_bits(m,stream,bits,14);
        memset(h2_ptr(m,scratch+0x14c,h2_read32(m,scratch+4)),0,h2_read32(m,scratch+4));
        h2_bitstream_write_buffer(m,stream,scratch+0x14c,bits);
    } else h2_write32(m,stream+16,h2_read32(m,stream+16)+1);
    uint32_t alignment=h2_read32(m,stream+8);
    uint32_t size=(uint32_t)(sv(h2_read32(m,stream+16)+7)/8);
    int64_t remainder=sv(size)%sv(alignment);
    h2_write32(m,stream+4,size);
    if(remainder) h2_write32(m,stream+4,size+alignment-(uint32_t)remainder);
    h2_write32(m,stream+12,2);
    h2_network_connection_send_packet(m,clock,send,stream,h2_read32(m,connection+0x44),
        h2_read32(m,connection),secondary_size,secondary,scratch+8,scratch+0x74c,workspace);
    uint32_t accounted=h2_read32(m,scratch+8);
    if(sv(accounted)>0) {h2_write32(m,scratch+0x24,h2_read32(m,stream+4));h2_write32(m,scratch+0x28,secondary_size);}
    if(h2_read32(m,scratch+12)!=UINT32_MAX) {
        uint32_t selected=h2_read32(m,0x4d87d8)+h2_read32(m,connection+16)*0x97c;
        h2_network_stream_record_size(m,selected,h2_read32(m,scratch+12),accounted);
    }
    uint32_t observer=h2_read32(m,connection+0x40);
    if(observer) (void)invoke(m,c,observer,0,3,h2_read32(m,connection+0x44),h2_read32(m,scratch+8),h2_read32(m,scratch+0x2c),0);
finish:
    if(accounted_output) h2_write32(m,accounted_output,h2_read32(m,scratch+8));
    if(primary_output) h2_write32(m,primary_output,h2_read32(m,scratch+0x24));
    if(secondary_output) h2_write32(m,secondary_output,h2_read32(m,scratch+0x28));
}
