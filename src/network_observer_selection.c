#include "halo2/network_observer_selection.h"
#include "internal/memory.h"
uint8_t h2_network_observer_select_address(h2_memory *m,const h2_network_query_platform *query,const h2_network_resolution_platform *resolution,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,const h2_network_registration_platform *registration,uint32_t observer,uint32_t index,uint32_t query_local,uint32_t detach_local,uint32_t resolution_local,uint32_t packet,uint8_t workspace[28]) {
    uint32_t entry=observer+0xa8+index*0x528;
    uint32_t status=h2_network_observer_query(m,query,observer,index,query_local);
    if (status==1 || status==2) return 1;
    h2_network_observer_detach(m,clock,send,codec,callbacks,registration,observer,index,0,0,detach_local,packet,workspace);
    for (uint32_t consumer=0;consumer<4;++consumer) {
        uint32_t bit=UINT32_C(1)<<consumer;
        if (!(*h2_ptr(m,entry+9,1)&bit) || (h2_read32(m,entry+0x38)&bit)) continue;
        if (h2_network_observer_resolve_address(m,resolution,observer,consumer,entry+0x14,entry+0x5c,entry+0x40,entry+0x44,entry+0x4c,resolution_local)) {
            h2_write32(m,entry+0x3c,consumer);
            return 1;
        }
    }
    return 0;
}
