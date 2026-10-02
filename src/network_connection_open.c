#include "halo2/network_connection_open.h"
#include "halo2/network_connection_setup.h"
#include "halo2/network_handshake.h"
#include "internal/memory.h"
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_connection_open(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,const h2_network_storage_operations *storage_ops,uint32_t connection,uint32_t address,uint8_t active,uint32_t message,uint32_t close_local,uint32_t storage_local,uint32_t packet,uint8_t workspace[28]) {
    for (uint32_t i=0;i<20;i+=4) h2_write32(m,connection+0x70+i,h2_read32(m,address+i));
    h2_write32(m,connection+0x54,3);*h2_ptr(m,connection+0x84,1)=active;
    const uint8_t *width=h2_ptr(m,address+18,2);
    if ((width[0]|(uint32_t)width[1]<<8)!=4 || h2_read32(m,address)!=0x7f000001)
        h2_write32(m,connection+0x48,h2_read32(m,connection+0x48)&0xffffff3fu);
    uint32_t endpoint=h2_read32(m,connection),sequence=h2_read32(m,endpoint+4),next=sequence+1;
    h2_write32(m,endpoint+4,next);
    if (next==UINT32_MAX) h2_write32(m,endpoint+4,0);
    uint32_t index=h2_read32(m,connection+0x44);
    endpoint=h2_read32(m,connection);
    h2_write32(m,connection+0x4c,sequence);h2_write32(m,connection+0x50,UINT32_MAX);
    if (!h2_network_endpoint_insert_route(m,clock,send,codec,callbacks,storage_ops,endpoint,index,sequence,connection+0x70,close_local,packet,storage_local,workspace)) {
        h2_network_connection_close(m,clock,send,codec,callbacks,connection,2,close_local,packet,workspace);
        return;
    }
    if (*h2_ptr(m,connection+0x84,1)) {
        uint32_t now=ticks(m,clock);h2_write32(m,connection+0x88,now);
        now=ticks(m,clock);h2_write32(m,connection+0x8c,now);
        h2_write32(m,connection+0x90,0);
        h2_network_connection_update_handshake(m,clock,send,codec,callbacks,connection,message,close_local,packet,workspace);
    }
    h2_network_connection_reset_timers(m,clock,connection);
    index=h2_read32(m,connection+0x10);
    if (index!=UINT32_MAX) h2_network_stream_reset(m,clock,h2_read32(m,0x4d87d8)+index*0x97c);
    index=h2_read32(m,connection+0x14);
    if (index!=UINT32_MAX) h2_network_storage_clear(m,storage_ops,h2_read32(m,0x4d87dc)+index*0x2850,storage_local);
}
