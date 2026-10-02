#include "halo2/network_handshake.h"
#include "internal/memory.h"
static int64_t signed32(uint32_t v) { return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v; }
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_connection_update_handshake(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,uint32_t connection,uint32_t message,uint32_t close_local,uint32_t packet,uint8_t workspace[28]) {
    uint32_t previous=h2_read32(m,connection+0x88),now=ticks(m,clock);
    uint32_t config=h2_read32(m,connection+12);
    if (signed32(now-previous)>=signed32(h2_read32(m,config+8))) {
        h2_network_connection_close(m,clock,send,codec,callbacks,connection,4,close_local,packet,workspace);
        return;
    }
    previous=h2_read32(m,connection+0x8c);now=ticks(m,clock);
    if (signed32(now-previous)<0) return;
    config=h2_read32(m,connection+12);
    if (signed32(h2_read32(m,connection+0x90))>=signed32(h2_read32(m,config+4))) return;
    uint32_t flags=h2_read32(m,connection+0x48),sequence=h2_read32(m,connection+0x4c);
    h2_write32(m,message+4,flags);h2_write32(m,message,sequence);
    h2_message_writer_enqueue(m,clock,send,codec,h2_read32(m,connection+4),connection+0x70,4,8,message,packet,workspace);
    uint32_t interval;
    if (*h2_ptr(m,0x510548,1)) {
        interval=h2_read32(m,h2_read32(m,connection+12));now=h2_read32(m,0x51054c);
    } else {
        now=clock->ticks(clock->context);interval=h2_read32(m,h2_read32(m,connection+12));
    }
    h2_write32(m,connection+0x8c,interval+now);
}
