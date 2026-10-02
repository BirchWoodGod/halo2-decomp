#include "halo2/network_observer_retry.h"
#include "halo2/network_resolution.h"
#include "internal/memory.h"
static int64_t signed32(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
uint32_t h2_network_elapsed(h2_memory *m,const h2_network_state_operations *clock,uint32_t previous) {
    return ticks(m,clock)-previous;
}
uint32_t h2_network_connection_send_capacity(h2_memory *m,uint32_t connection) {
    if (h2_read32(m,connection+0x54)!=5 || !(*h2_ptr(m,connection+0x48,1)&16)) return 0;
    uint32_t storage=h2_read32(m,connection+0x14)*0x2850+h2_read32(m,0x4d87dc);
    uint32_t last=h2_read32(m,storage+0x18);
    return (h2_read32(m,storage+0x1c)-last+512)*32;
}
uint8_t h2_network_observer_retry_allowed(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,uint32_t observer,uint32_t index,uint32_t reason,uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    uint32_t entry=observer+0xa8+index*0x528,id=h2_read32(m,entry+12);uint8_t available=1;
    if (id!=UINT32_MAX) {
        uint32_t connection=h2_read32(m,0x4d87d4)+id*0xf8;
        if (h2_read32(m,connection+0x54)==5) {
            if (signed32(h2_network_connection_send_capacity(m,connection))<0x4000) available=0;
            else h2_network_connection_close(m,clock,send,codec,callbacks,connection,reason,local,packet,workspace);
        }
    }
    if (!h2_read32(m,entry+0x98)) h2_write32(m,entry+0x98,ticks(m,clock));
    uint32_t previous=h2_read32(m,entry+0x98),now=ticks(m,clock);
    uint8_t timeout=signed32(now-previous)>signed32(h2_read32(m,0x4cf56c));
    if (available) {
        if (!h2_read32(m,entry+0x9c)) h2_write32(m,entry+0x9c,ticks(m,clock));
        previous=h2_read32(m,entry+0x9c);now=ticks(m,clock);
        if (timeout || signed32(now-previous)>signed32(h2_read32(m,0x4cf568))) return 1;
    } else {
        h2_write32(m,entry+0x9c,0);
        if (timeout) return 1;
    }
    return !h2_network_address_valid(m,entry+0x5c);
}
