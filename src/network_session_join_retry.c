#include "halo2/network_session_join_retry.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
void h2_network_session_resend_join(h2_memory *m,const h2_network_query_platform *query,
    const h2_network_state_operations *clock,const h2_socket_send_platform *send,
    const h2_message_codec_platform *codec,uint32_t session,uint32_t payload,
    uint32_t query_scratch,uint32_t packet,uint8_t workspace[28]) {
    if(h2_network_observer_query(m,query,h2_read32(m,session+8),h2_read32(m,session+0x7420),query_scratch)!=2) return;
    uint8_t cached=*h2_ptr(m,0x510548,1);
    uint32_t previous=h2_read32(m,session+0x7614);
    uint32_t now=cached ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    if(sv(now-previous)<=sv(h2_read32(m,0x4cf494))) return;
    memset(h2_ptr(m,payload,0x1b8),0,0x1b8);
    uint32_t high=h2_read32(m,session+0x20),low=h2_read32(m,session+0x1c);
    h2_write32(m,payload+8,high);h2_write32(m,payload+4,low);
    *h2_ptr(m,payload,1)=2;
    for(uint32_t i=0;i<0x1ac;i+=4) h2_write32(m,payload+12+i,h2_read32(m,session+0x745c+i));
    (void)h2_message_writer_enqueue(m,clock,send,codec,h2_read32(m,session+4),session+0x7448,8,0x1b8,payload,packet,workspace);
    uint32_t count=h2_read32(m,session+0x7610)+1;cached=*h2_ptr(m,0x510548,1);
    h2_write32(m,session+0x7610,count);
    now=cached ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,session+0x7614,now);
}
