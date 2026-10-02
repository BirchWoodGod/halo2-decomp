#include "halo2/network_observer_admission.h"
#include "internal/memory.h"
void h2_network_observer_close_established(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,uint32_t observer,uint32_t index,uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    uint32_t identifier=h2_read32(m,observer+0xa8+index*0x528+12);
    if (identifier==UINT32_MAX) return;
    uint32_t connection=h2_read32(m,0x4d87d4)+identifier*0xf8;
    uint32_t state=h2_read32(m,connection+0x54);
    if ((state&0x80000000u) || state<=2) return;
    h2_network_connection_close(m,clock,send,codec,callbacks,connection,17,local,packet,workspace);
}
