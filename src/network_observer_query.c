#include "halo2/network_observer_query.h"
#include "internal/memory.h"
uint32_t h2_network_address_query(h2_memory *m,const h2_network_query_platform *p,uint32_t address,uint32_t scratch) {
    h2_write32(m,scratch,address);
    if (!h2_network_address_registered_ipv4(m,address,scratch)) return 4;
    uint32_t result=p->query(p->context,h2_read32(m,scratch));
    return result<=3 ? result : 4;
}
uint32_t h2_network_observer_query(h2_memory *m,const h2_network_query_platform *p,uint32_t observer,uint32_t index,uint32_t scratch) {
    uint32_t address=observer+0xa8+index*0x528+0x5c;
    if (!h2_network_address_valid(m,address)) return 0;
    return h2_network_address_query(m,p,address,scratch);
}
void h2_network_observer_refresh_address(h2_memory *m,const h2_network_query_platform *p,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,const h2_network_registration_platform *registration,const h2_observer_events *events,uint32_t observer,uint32_t index,uint32_t query,uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    uint32_t entry=observer+0xa8+index*0x528,state=h2_read32(m,entry);
    if (state<=2) return;
    uint32_t result=h2_network_observer_query(m,p,observer,index,query);
    if (state==3) {
        if (result==2) {h2_network_observer_set_state(m,clock,events,observer,index,4);return;}
        if (result==1) return;
        h2_network_observer_detach(m,clock,send,codec,callbacks,registration,observer,index,1,0,local,packet,workspace);
        h2_network_observer_set_state(m,clock,events,observer,index,2);
        uint8_t *b=h2_ptr(m,entry+10,2);uint32_t retry=(b[0]|(uint32_t)b[1]<<8)+1;
        b[0]=(uint8_t)retry;b[1]=(uint8_t)(retry>>8);
    } else if (result!=2) {
        h2_network_observer_detach(m,clock,send,codec,callbacks,registration,observer,index,1,13,local,packet,workspace);
        h2_network_observer_set_state(m,clock,events,observer,index,2);
        uint8_t *b=h2_ptr(m,entry+10,2);b[0]=0;b[1]=0;
    }
}
