#include "halo2/network_connection.h"
#include "halo2/network_routing.h"
#include "internal/memory.h"
static int64_t connection_signed(uint32_t x) {
    return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;
}
void h2_network_connection_close(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    uint32_t connection,uint32_t reason,uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    if (h2_read32(m,connection+0x54)==5 && reason!=6) {
        uint32_t remote=h2_read32(m,connection+0x4c),local_id=h2_read32(m,connection+0x50);
        h2_write32(m,local+4,remote);h2_write32(m,local,local_id);
        uint32_t writer=h2_read32(m,connection+4);
        h2_write32(m,local+8,reason);
        h2_message_writer_enqueue(m,clock,send,codec,writer,connection+0x70,7,12,local,packet,workspace);
    }
    uint32_t callback=h2_read32(m,connection+0x3c);
    if (callback) {
        uint32_t argument=h2_read32(m,callback+4),function=h2_read32(m,callback+8);
        callbacks->closed(callbacks->context,function,argument);
    }
    uint32_t endpoint=h2_read32(m,connection),id=h2_read32(m,connection+0x44);
    h2_network_endpoint_remove_route(m,endpoint,id);
    for (uint32_t i=0;i<20;i+=4) h2_write32(m,connection+0x5c+i,h2_read32(m,connection+0x70+i));
    h2_write32(m,connection+0x54,2);h2_write32(m,connection+0x58,reason);
    h2_write32(m,connection+0x4c,UINT32_MAX);h2_write32(m,connection+0x50,UINT32_MAX);
}
void h2_network_endpoint_close_connections(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    uint32_t endpoint,uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    for (uint32_t i=0;connection_signed(i)<connection_signed(h2_read32(m,endpoint+0x20));++i) {
        uint32_t id=h2_read32(m,endpoint+0x24+i*32);
        uint32_t connection=h2_read32(m,0x4d87d4)+id*0xf8;
        h2_network_connection_close(m,clock,send,codec,callbacks,connection,1,local,packet,workspace);
    }
    h2_write32(m,endpoint+0x20,0);
}

void h2_network_connection_dispose(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    const h2_network_storage_operations *storage_ops,uint32_t connection,uint32_t local,
    uint32_t packet,uint32_t storage_scratch,uint8_t workspace[28]) {
    if (connection_signed(h2_read32(m,connection+0x54))>2)
        h2_network_connection_close(m,clock,send,codec,callbacks,connection,3,local,packet,workspace);
    uint32_t index=h2_read32(m,connection+0x14);
    h2_write32(m,connection+0x40,0);
    if (index!=UINT32_MAX) {
        uint32_t storage=h2_read32(m,0x4d87dc)+index*0x2850;
        h2_network_storage_clear(m,storage_ops,storage,storage_scratch);
        *h2_ptr(m,storage+4,1)=0;h2_write32(m,storage+8,0);
        h2_write32(m,connection+0x14,UINT32_MAX);
    }
    index=h2_read32(m,connection+0x10);
    if (index!=UINT32_MAX) {
        uint32_t storage=h2_read32(m,0x4d87d8)+index*0x97c;
        *h2_ptr(m,storage+4,1)=0;h2_write32(m,storage+8,0);
        h2_write32(m,connection+0x10,UINT32_MAX);
    }
    h2_write32(m,connection+0x54,0);
}
