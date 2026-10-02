#include "halo2/network_observer.h"
#include "internal/memory.h"
void h2_network_observer_send(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_network_resolution_platform *resolution,const h2_network_storage_queue_operations *queue,uint32_t observer,uint32_t index,uint32_t consumer,uint8_t unreliable,uint32_t type,uint32_t size,uint32_t payload,uint32_t local,uint32_t reliable,uint32_t packet,uint8_t workspace[28]) {
    h2_write32(m,local+44,observer);
    uint32_t entry=observer+0xa8+index*0x528,identifier=h2_read32(m,entry+12);
    if (identifier==UINT32_MAX) return;
    uint32_t connection=h2_read32(m,0x4d87d4)+identifier*0xf8;
    h2_write32(m,local+44,connection);
    if (unreliable) {
        if (h2_network_address_valid(m,entry+0x5c)) {
            for (uint32_t i=0;i<5;++i) h2_write32(m,local+24+i*4,h2_read32(m,entry+0x5c+i*4));
        } else if (!h2_network_observer_resolve_address(m,resolution,observer,consumer,entry+0x14,local+24,local+44,local,local+8,local+48)) return;
        (void)h2_message_writer_enqueue(m,clock,send,codec,h2_read32(m,observer+8),local+24,type,size,payload,packet,workspace);
    } else {
        uint32_t state=h2_read32(m,connection+0x54);
        if ((state&0x80000000u) || state<=2) return;
        uint32_t count=type&255;
        uint64_t mask=count<64 ? UINT64_C(1)<<count : 0;
        uint32_t low=h2_read32(m,entry+0x520),high=h2_read32(m,entry+0x524);
        if ((low&(uint32_t)mask) || (high&(uint32_t)(mask>>32))) {
            h2_write32(m,entry+0x520,low&~(uint32_t)mask);h2_write32(m,entry+0x524,high&~(uint32_t)(mask>>32));
        }
        uint32_t storage=h2_read32(m,connection+0x14)*0x2850+h2_read32(m,0x4d87dc);
        h2_network_storage_enqueue(m,queue,codec,storage,type,size,payload,reliable);
    }
}
