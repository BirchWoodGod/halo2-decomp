#include "halo2/network_connection_accept.h"
#include "halo2/network_connection_setup.h"
#include "internal/memory.h"
void h2_network_connection_send_accept(h2_memory *m,const h2_connection_accept_context *c,uint32_t connection,uint8_t reliable) {
    uint32_t local=h2_read32(m,connection+0x4c),remote=h2_read32(m,connection+0x50);
    h2_write32(m,c->message8+4,local);h2_write32(m,c->message8,remote);
    if(*h2_ptr(m,connection+0x48,1)&0x10) {
        if(reliable) {
            uint32_t storage=h2_read32(m,0x4d87dc)+h2_read32(m,connection+0x14)*0x2850u;
            h2_network_storage_enqueue(m,c->queue,c->codec,storage,6,8,c->message8,c->storage_scratch);
        }
    } else h2_message_writer_enqueue(m,c->clock,c->send,c->codec,h2_read32(m,connection+4),connection+0x70,6,8,c->message8,c->packet,c->workspace28);
}
void h2_network_connection_accept(h2_memory *m,const h2_connection_accept_context *c,uint32_t connection,uint32_t remote_id) {
    uint8_t reliable=0;
    if(h2_read32(m,connection+0x54)==3) {
        uint8_t override=*h2_ptr(m,0x510548,1);
        h2_write32(m,connection+0x54,4);
        uint32_t now=override ? h2_read32(m,0x51054c) : c->clock->ticks(c->clock->context);
        h2_write32(m,connection+0x94,now);h2_write32(m,connection+0x50,remote_id);
        reliable=1;
        h2_network_connection_reset_timers(m,c->clock,connection);
        if(!(*h2_ptr(m,connection+0x48,1)&0x10)) h2_write32(m,connection+0x54,5);
    }
    h2_network_connection_send_accept(m,c,connection,reliable);
}
