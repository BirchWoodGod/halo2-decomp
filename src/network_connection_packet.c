#include "halo2/network_connection_packet.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static void copy(h2_memory *m,uint32_t dst,uint32_t src,uint32_t count) {
    uint32_t words=count/4;
    for(uint32_t i=0;i<words;++i) h2_write32(m,dst+i*4,h2_read32(m,src+i*4));
    for(uint32_t i=words*4;i<count;++i) *h2_ptr(m,dst+i,1)=*h2_ptr(m,src+i,1);
}
void h2_network_connection_send_packet(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,uint32_t stream,uint32_t index,uint32_t endpoint,uint32_t secondary_size,uint32_t secondary,uint32_t size_output,uint32_t scratch,uint8_t workspace[28]) {
    uint32_t connection=h2_read32(m,0x4d87d4)+index*0xf8,accounted=0;
    memset(h2_ptr(m,scratch,0x824),0,0x824);
    uint32_t state=h2_read32(m,connection+0x54);
    if(state==0 || state==1) goto finish;
    copy(m,scratch+8,connection+0x70,20);
    const uint8_t *width=h2_ptr(m,scratch+0x1a,2);
    if(width[0]==4 && width[1]==0 && h2_read32(m,scratch+8)==0x7f000001) {
        if(sv(state)<=2) goto finish;
        uint8_t flags=*h2_ptr(m,connection+0x48,1);
        if(flags&0x40) h2_write32(m,scratch,1);
        else if(flags&0x80) h2_write32(m,scratch,2);
        else goto finish;
    }
    if(stream) {
        uint32_t size=h2_read32(m,stream+4);h2_write32(m,scratch+0x1c,size);
        if(size>0x600) goto finish;
        copy(m,scratch+0x20,h2_read32(m,stream),size);
    }
    if(sv(secondary_size)>0) {
        h2_write32(m,scratch+0x620,secondary_size);
        if(secondary_size>0x200) goto finish;
        copy(m,scratch+0x624,secondary,secondary_size);
    }
    h2_network_packet_submit(m,clock,send,scratch,endpoint,scratch+0x824,workspace);
    accounted=h2_network_packet_accounted_size(m,scratch);
finish:
    if(size_output) h2_write32(m,size_output,accounted);
}
